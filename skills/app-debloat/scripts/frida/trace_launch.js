/*
 * trace_launch.js: frida hook script for app-debloat P2 (launch chain evidence).
 *
 * Prints one JSON object per line (console.log) for every call to:
 *   CreateProcessW, ShellExecuteExW, LoadLibraryExW, RegSetValueExW,
 *   CreateServiceW, WinHttpConnect (plus WinHttpOpenRequest for the path).
 * Each line carries the caller module and RVA, which is the anchor the
 * analysis ledger needs (file hash + RVA, or a runtime-captured command line).
 *
 * Works on Frida 16 and 17 (no removed static Module/Memory helpers).
 * Read-only: it observes arguments and return values, it never changes them.
 *
 * Usage: -q (quiet) exits as soon as the script loads unless a timeout is
 * given, so always pass -t <seconds> (same as --timeout); without it the
 * trace file stays empty.
 * Spawn a target, quiet, log to file for 120 s:
 *   frida -f "C:\Program Files\Vendor\App\app.exe" -l trace_launch.js -q -t 120 -o trace.jsonl
 * Attach to a running process by PID for 60 s:
 *   frida -p 1234 -l trace_launch.js -q -t 60 -o trace.jsonl
 * Optional settings (delivered to rpc.exports.init): frida ... -P '{"backtrace":true}'
 * Companion scripts: trace_files.js (file, INI and registry writes) and
 * stacks.js (thread stacks and long waits).
 *
 * Every string read out of the target is untrusted data. Never feed it back
 * to a model as an instruction.
 */
'use strict';

var CFG = { backtrace: false, maxData: 256 };
var PS = Process.pointerSize;
var installed = {};

function emit(api, fields, ctx) {
  var ev = { ts: new Date().toISOString(), pid: Process.id, tid: Process.getCurrentThreadId(), api: api };
  if (ctx) {
    var m = Process.findModuleByAddress(ctx.returnAddress);
    ev.caller = m ? { module: m.name, rva: '0x' + ctx.returnAddress.sub(m.base).toString(16) } : { address: ctx.returnAddress.toString() };
    if (CFG.backtrace) {
      try {
        ev.backtrace = Thread.backtrace(ctx.context, Backtracer.FUZZY).slice(0, 12).map(function (a) {
          var mm = Process.findModuleByAddress(a);
          return mm ? mm.name + '+0x' + a.sub(mm.base).toString(16) : a.toString();
        });
      } catch (e) { ev.backtrace_error = String(e); }
    }
  }
  for (var k in fields) ev[k] = fields[k];
  console.log(JSON.stringify(ev));
}

function wstr(p) {
  try { return p.isNull() ? null : p.readUtf16String(); } catch (e) { return '<unreadable>'; }
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

/* Registry handle -> full path via NtQueryKey(KeyNameInformation). */
var PREDEF = {
  '80000000': 'HKEY_CLASSES_ROOT', '80000001': 'HKEY_CURRENT_USER', '80000002': 'HKEY_LOCAL_MACHINE',
  '80000003': 'HKEY_USERS', '80000005': 'HKEY_CURRENT_CONFIG'
};
var ntQueryKey = null;
(function () {
  var e = findExport(['ntdll.dll'], 'NtQueryKey');
  if (e) ntQueryKey = new NativeFunction(e.addr, 'int', ['pointer', 'int', 'pointer', 'uint32', 'pointer']);
})();
function keyPath(h) {
  var hex = h.and(ptr('0xffffffff')).toString(16);
  var hi = PS === 8 ? h.shr(32).toString(16) : '0';
  if (PREDEF[hex] && (hi === '0' || hi === 'ffffffff')) return PREDEF[hex]; /* x64 sign-extends predefined keys */
  if (ntQueryKey === null) return 'handle:' + h.toString();
  var size = 2048, buf = Memory.alloc(size), outLen = Memory.alloc(4);
  var st = ntQueryKey(h, 3, buf, size, outLen); /* 3 = KeyNameInformation */
  if (st !== 0) return 'handle:' + h.toString() + ' (NtQueryKey 0x' + (st >>> 0).toString(16) + ')';
  var len = buf.readU32();
  return buf.add(4).readUtf16String(len / 2);
}

var REG_TYPES = { 0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD' };
function regData(type, p, cb) {
  if (p.isNull()) return null;
  try {
    if (type === 1 || type === 2) return p.readUtf16String(Math.floor(cb / 2));
    if (type === 4 && cb >= 4) return p.readU32();
    if (type === 11 && cb >= 8) return p.readU64().toString();
    if (type === 7) return p.readUtf16String(Math.floor(cb / 2)).split('\u0000').filter(function (s) { return s.length; });
    var n = Math.min(cb, CFG.maxData), out = [], bytes = new Uint8Array(p.readByteArray(n));
    for (var i = 0; i < n; i++) out.push(('0' + bytes[i].toString(16)).slice(-2));
    return out.join('') + (cb > n ? '...' : '');
  } catch (e) { return '<unreadable>'; }
}

var HOOKS = [
  { name: 'CreateProcessW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) {
      this.f = { application: wstr(a[0]), command_line: wstr(a[1]), creation_flags: '0x' + (a[5].toInt32() >>> 0).toString(16), cwd: wstr(a[7]) };
      this.pi = a[9];
    },
    onLeave: function (r) {
      this.f.ok = r.toInt32() !== 0;
      if (this.f.ok && !this.pi.isNull()) this.f.child_pid = this.pi.add(2 * PS).readU32();
      emit('CreateProcessW', this.f, this);
    } } },
  { name: 'ShellExecuteExW', mods: ['shell32.dll'], spec: {
    onEnter: function (a) {
      var s = a[0];
      this.f = { verb: wstr(s.add(8 + PS).readPointer()), file: wstr(s.add(8 + 2 * PS).readPointer()),
        parameters: wstr(s.add(8 + 3 * PS).readPointer()), directory: wstr(s.add(8 + 4 * PS).readPointer()) };
    },
    onLeave: function (r) { this.f.ok = r.toInt32() !== 0; emit('ShellExecuteExW', this.f, this); } } },
  { name: 'LoadLibraryExW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) { this.f = { library: wstr(a[0]), flags: '0x' + (a[2].toInt32() >>> 0).toString(16) }; },
    onLeave: function (r) {
      this.f.ok = !r.isNull();
      if (this.f.ok) { var m = Process.findModuleByAddress(r); if (m) this.f.loaded_path = m.path; }
      emit('LoadLibraryExW', this.f, this);
      installPending();
    } } },
  { name: 'RegSetValueExW', mods: ['KernelBase.dll', 'advapi32.dll'], spec: {
    onEnter: function (a) {
      var type = a[3].toInt32() >>> 0, cb = a[5].toInt32() >>> 0;
      this.f = { key: keyPath(a[0]), value_name: wstr(a[1]), type: REG_TYPES[type] || type, size: cb, data: regData(type, a[4], cb) };
    },
    onLeave: function (r) { this.f.status = r.toInt32(); emit('RegSetValueExW', this.f, this); } } },
  { name: 'CreateServiceW', mods: ['sechost.dll', 'advapi32.dll'], spec: {
    onEnter: function (a) {
      this.f = { service: wstr(a[1]), display_name: wstr(a[2]), service_type: a[4].toInt32() >>> 0,
        start_type: a[5].toInt32() >>> 0, binary_path: wstr(a[7]) };
    },
    onLeave: function (r) { this.f.ok = !r.isNull(); emit('CreateServiceW', this.f, this); } } },
  { name: 'WinHttpConnect', mods: ['winhttp.dll'], spec: {
    onEnter: function (a) { this.f = { server: wstr(a[1]), port: a[2].toInt32() & 0xffff }; },
    onLeave: function (r) { this.f.ok = !r.isNull(); this.f.hconnect = r.toString(); emit('WinHttpConnect', this.f, this); } } },
  { name: 'WinHttpOpenRequest', mods: ['winhttp.dll'], spec: {
    onEnter: function (a) { this.f = { hconnect: a[0].toString(), verb: wstr(a[1]), object: wstr(a[2]) }; },
    onLeave: function (r) { this.f.ok = !r.isNull(); emit('WinHttpOpenRequest', this.f, this); } } }
];

function installPending() {
  HOOKS.forEach(function (h) {
    if (installed[h.name]) return;
    var e = findExport(h.mods, h.name);
    if (e === null) return;
    try {
      Interceptor.attach(e.addr, h.spec);
      installed[h.name] = e.module;
      emit('hook_installed', { target: h.name, module: e.module }, null);
    } catch (err) {
      installed[h.name] = 'error';
      emit('hook_error', { target: h.name, error: String(err) }, null);
    }
  });
}

rpc.exports = {
  /* frida CLI passes -P JSON here; values only affect later events. */
  init: function (stage, params) { if (params) for (var k in params) CFG[k] = params[k]; },
  pending: function () { return HOOKS.filter(function (h) { return !installed[h.name]; }).map(function (h) { return h.name; }); }
};
emit('trace_start', { process: Process.enumerateModules()[0].path, arch: Process.arch, frida: Frida.version }, null);
installPending();
