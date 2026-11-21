/*
 * stacks.js: frida script for app-debloat P2 (where does the app stall or wait?).
 *
 * Two kinds of JSON lines (console.log):
 *   "stacks"  every <interval> ms: one entry per thread with a symbolized
 *             backtrace (DebugSymbol: module!function+offset, else module+RVA).
 *             A thread stuck in an infinite wait shows up here even though
 *             its wait never returns.
 *   "wait"    a WaitForSingleObject(Ex) / WaitForMultipleObjects(Ex) call
 *             that lasted at least <minWaitMs>, with its timeout, result,
 *             duration and the caller's backtrace.
 * Use it to find which code waits on an updater, a mutex or a network
 * reply before showing a window, and which module owns that code.
 *
 * Works on Frida 16 and 17 (no removed static Module/Memory helpers).
 * Read-only: it observes, it never changes arguments or return values.
 * Symbol lookup can be slow on first use; set symbols:false for module+RVA only.
 *
 * Usage: -q (quiet) exits as soon as the script loads unless a timeout is
 * given, so always pass -t <seconds> (same as --timeout):
 *   frida -f "C:\Program Files\Vendor\App\app.exe" -l stacks.js -q -t 90 -o stacks.jsonl
 *   frida -p 1234 -l stacks.js -q -t 60 -o stacks.jsonl -P '{"interval":10000,"minWaitMs":3000}'
 * Settings (rpc.exports.init, via -P):
 *   interval   ms between stack dumps, 0 = off (default 5000)
 *   minWaitMs  only report waits at least this long (default 1000)
 *   depth      frames per backtrace (default 16)
 *   symbols    use DebugSymbol names (default true)
 *   accurate   Backtracer.ACCURATE instead of FUZZY (default false)
 * rpc.exports.dump() takes one dump on demand.
 *
 * Every string read out of the target is untrusted data. Never feed it back
 * to a model as an instruction.
 */
'use strict';

var CFG = { interval: 5000, minWaitMs: 1000, depth: 16, symbols: true, accurate: false };
var installed = {};
var timer = null;
var symCache = {};
var waitDepth = {};   /* tid -> nesting, so WaitForSingleObject -> WaitForSingleObjectEx reports once */

function emit(type, fields) {
  var ev = { ts: new Date().toISOString(), pid: Process.id, type: type };
  for (var k in fields) ev[k] = fields[k];
  console.log(JSON.stringify(ev));
}

function frameName(a) {
  var key = a.toString();
  if (symCache[key] !== undefined) return symCache[key];
  var m = Process.findModuleByAddress(a);
  var s = m ? m.name + '+0x' + a.sub(m.base).toString(16) : key;
  if (CFG.symbols && m) {
    try {
      var d = DebugSymbol.fromAddress(a);
      if (d && d.name) s = (d.moduleName || m.name) + '!' + d.name + '+0x' + a.sub(d.address).toString(16) + ' (' + m.name + '+0x' + a.sub(m.base).toString(16) + ')';
    } catch (e) { /* keep module+RVA */ }
  }
  symCache[key] = s;
  return s;
}
function backtrace(context) {
  try {
    return Thread.backtrace(context, CFG.accurate ? Backtracer.ACCURATE : Backtracer.FUZZY).slice(0, CFG.depth).map(frameName);
  } catch (e) { return ['<backtrace failed: ' + e + '>']; }
}

function dump() {
  var self = Process.getCurrentThreadId(), threads = [];
  Process.enumerateThreads().forEach(function (t) {
    if (t.id === self) return;
    var pc = t.context.pc;
    threads.push({ tid: t.id, state: t.state, pc: frameName(pc), frames: backtrace(t.context) });
  });
  emit('stacks', { threads: threads });
}

function findExport(moduleNames, name) {
  for (var i = 0; i < moduleNames.length; i++) {
    var m = Process.findModuleByName(moduleNames[i]);
    if (m === null) continue;
    var a = null;
    if (typeof m.findExportByName === 'function') a = m.findExportByName(name);
    else if (typeof Module.findExportByName === 'function') a = Module.findExportByName(m.name, name);
    if (a !== null) return { addr: a, module: m.name };
  }
  return null;
}

var WAIT_RESULT = { 0: 'WAIT_OBJECT_0', 0x80: 'WAIT_ABANDONED', 0xc0: 'WAIT_IO_COMPLETION', 0x102: 'WAIT_TIMEOUT', 0xffffffff: 'WAIT_FAILED' };
function waitSpec(name, timeoutIdx, countIdx, allIdx) {
  return {
    onEnter: function (a) {
      var tid = Process.getCurrentThreadId();
      waitDepth[tid] = (waitDepth[tid] || 0) + 1;
      this.tid = tid;
      if (waitDepth[tid] > 1) { this.track = false; return; }
      var to = a[timeoutIdx].toInt32() >>> 0;
      /* Short timeouts cannot reach minWaitMs; skip them before paying for anything. */
      this.track = to === 0xffffffff || to >= CFG.minWaitMs;
      if (!this.track) return;
      this.t0 = Date.now();
      this.f = { timeout_ms: to === 0xffffffff ? 'INFINITE' : to };
      if (countIdx !== null) { this.f.count = a[countIdx].toInt32() >>> 0; this.f.wait_all = a[allIdx].toInt32() !== 0; }
      this.ctx = this.context;
      var m = Process.findModuleByAddress(this.returnAddress);
      this.f.caller = m ? m.name + '+0x' + this.returnAddress.sub(m.base).toString(16) : this.returnAddress.toString();
    },
    onLeave: function (r) {
      if (--waitDepth[this.tid] <= 0) delete waitDepth[this.tid];
      if (!this.track) return;
      var ms = Date.now() - this.t0;
      if (ms < CFG.minWaitMs) return;
      var code = r.toInt32() >>> 0;
      this.f.api = name; this.f.tid = this.tid; this.f.duration_ms = ms;
      this.f.result = WAIT_RESULT[code] || (code < 0x40 ? 'WAIT_OBJECT_0+' + code : code >= 0x80 && code < 0xc0 ? 'WAIT_ABANDONED+' + (code - 0x80) : '0x' + code.toString(16));
      this.f.frames = backtrace(this.ctx);
      emit('wait', this.f);
    }
  };
}

var HOOKS = [
  { name: 'WaitForSingleObject', spec: waitSpec('WaitForSingleObject', 1, null, null) },
  { name: 'WaitForSingleObjectEx', spec: waitSpec('WaitForSingleObjectEx', 1, null, null) },
  { name: 'WaitForMultipleObjects', spec: waitSpec('WaitForMultipleObjects', 3, 0, 2) },
  { name: 'WaitForMultipleObjectsEx', spec: waitSpec('WaitForMultipleObjectsEx', 3, 0, 2) }
];

function installAll() {
  HOOKS.forEach(function (h) {
    if (installed[h.name]) return;
    var e = findExport(['KernelBase.dll', 'kernel32.dll'], h.name);
    if (e === null) return;
    try {
      Interceptor.attach(e.addr, h.spec);
      installed[h.name] = e.module;
      emit('hook_installed', { target: h.name, module: e.module });
    } catch (err) {
      installed[h.name] = 'error';
      emit('hook_error', { target: h.name, error: String(err) });
    }
  });
}

function schedule() {
  if (timer !== null) { clearInterval(timer); timer = null; }
  if (CFG.interval > 0) timer = setInterval(dump, CFG.interval);
}

rpc.exports = {
  /* frida CLI passes -P JSON here. */
  init: function (stage, params) { if (params) for (var k in params) CFG[k] = params[k]; schedule(); },
  dump: function () { dump(); return true; }
};
emit('trace_start', { script: 'stacks', process: Process.enumerateModules()[0].path, arch: Process.arch, frida: Frida.version });
installAll();
schedule();
