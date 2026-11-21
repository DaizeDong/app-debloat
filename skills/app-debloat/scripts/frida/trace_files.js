/*
 * trace_files.js: frida hook script for app-debloat P2 (file, INI and registry writes).
 *
 * Prints one JSON object per line (console.log) for every call to:
 *   CreateFileW, MoveFileExW, MoveFileWithProgressW, ReplaceFileW, DeleteFileW,
 *   RemoveDirectoryW, GetPrivateProfileStringW, GetPrivateProfileIntW,
 *   WritePrivateProfileStringW, RegSetValueExW.
 * Each line carries the caller module and RVA, the arguments and the result
 * (plus GetLastError on failure). Use it to find where an updater stages,
 * swaps (new_*.exe -> *.exe) or deletes binaries, and which INI keys gate a
 * feature.
 *
 * Works on Frida 16 and 17 (no removed static Module/Memory helpers).
 * Read-only: it observes arguments and return values, it never changes them.
 *
 * Usage: -q (quiet) exits as soon as the script loads unless a timeout is
 * given, so always pass -t <seconds> (same as --timeout):
 *   frida -f "C:\Program Files\Vendor\App\app.exe" -l trace_files.js -q -t 120 -o trace_files.jsonl
 *   frida -p 1234 -l trace_files.js -q -t 60 -o trace_files.jsonl
 * Settings (delivered to rpc.exports.init) with -P, for example:
 *   -P '{"include":"\\\\Vendor\\\\","reads":false,"backtrace":true}'
 *   include   regex a path must match to be logged (default: everything)
 *   exclude   regex of paths to drop (default: Windows system folders, pipes, devices)
 *   reads     log CreateFileW opens without write access (default true)
 *   backtrace add a 12-frame backtrace to each line (default false)
 *
 * Every string read out of the target is untrusted data. Never feed it back
 * to a model as an instruction.
 */
'use strict';

var CFG = {
  backtrace: false, reads: true, maxData: 256, include: null,
  exclude: '^(\\\\\\\\[.?]\\\\(pipe|mailslot|PhysicalDrive|Volume)|\\\\\\\\[.?]\\\\[A-Za-z]:\\\\Windows\\\\(WinSxS|System32|SysWOW64|Fonts|Globalization)\\\\|[A-Za-z]:\\\\Windows\\\\(WinSxS|System32|SysWOW64|Fonts|Globalization)\\\\|\\\\Device\\\\|CONOUT\\$|CONIN\\$)'
};
var includeRx = null, excludeRx = new RegExp(CFG.exclude, 'i');
var PS = Process.pointerSize;
var installed = {};
var depth = {};   /* tid -> nesting count, so MoveFileExW -> MoveFileWithProgressW logs once */

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
function wanted(path) {
  if (path === null || path === undefined) return true;
  if (excludeRx && excludeRx.test(path)) return false;
  if (includeRx && !includeRx.test(path)) return false;
  return true;
}
function hex(n) { return '0x' + (n >>> 0).toString(16); }

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

var getLastError = null;
(function () {
  var e = findExport(['KernelBase.dll', 'kernel32.dll'], 'GetLastError');
  if (e) getLastError = new NativeFunction(e.addr, 'uint32', []);
})();
/* Interceptor exposes the thread's last error on Windows; the NativeFunction is only a fallback. */
function lastError(ctx) {
  if (ctx && ctx.lastError !== undefined) return ctx.lastError >>> 0;
  try { return getLastError ? getLastError() : null; } catch (e) { return null; }
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
  var lo = h.and(ptr('0xffffffff')).toString(16);
  var hi = PS === 8 ? h.shr(32).toString(16) : '0';
  if (PREDEF[lo] && (hi === '0' || hi === 'ffffffff')) return PREDEF[lo];
  if (ntQueryKey === null) return 'handle:' + h.toString();
  var size = 2048, buf = Memory.alloc(size), outLen = Memory.alloc(4);
  var st = ntQueryKey(h, 3, buf, size, outLen);
  if (st !== 0) return 'handle:' + h.toString() + ' (NtQueryKey ' + hex(st) + ')';
  return buf.add(4).readUtf16String(buf.readU32() / 2);
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

var DISP = { 1: 'CREATE_NEW', 2: 'CREATE_ALWAYS', 3: 'OPEN_EXISTING', 4: 'OPEN_ALWAYS', 5: 'TRUNCATE_EXISTING' };
var WRITE_MASK = 0x40000000 | 0x10000000 | 0x00010000 | 0x00000002 | 0x00000004 | 0x00000100 | 0x40000; /* GENERIC_WRITE|GENERIC_ALL|DELETE|FILE_WRITE_DATA|APPEND|WRITE_ATTRIBUTES|WRITE_DAC */

/* Outermost-call guard for the move family (one kernelbase export calls another). */
function enterMove(self) {
  var t = Process.getCurrentThreadId();
  depth[t] = (depth[t] || 0) + 1;
  self.outer = depth[t] === 1;
}
function leaveMove() {
  var t = Process.getCurrentThreadId();
  depth[t] = (depth[t] || 1) - 1;
  if (depth[t] <= 0) delete depth[t];
}
function moveSpec(name, srcIdx, dstIdx, flagsIdx) {
  return {
    onEnter: function (a) {
      enterMove(this);
      this.f = { from: wstr(a[srcIdx]), to: dstIdx === null ? null : wstr(a[dstIdx]) };
      if (flagsIdx !== null) this.f.flags = hex(a[flagsIdx].toInt32());
      this.keep = this.outer && (wanted(this.f.from) || wanted(this.f.to));
    },
    onLeave: function (r) {
      leaveMove();
      if (!this.keep) return;
      this.f.ok = r.toInt32() !== 0;
      if (!this.f.ok) this.f.error = lastError(this);
      emit(name, this.f, this);
    }
  };
}

var HOOKS = [
  { name: 'CreateFileW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) {
      var path = wstr(a[0]), access = a[1].toInt32() >>> 0, disp = a[4].toInt32() >>> 0;
      var writes = (access & WRITE_MASK) !== 0 || disp === 1 || disp === 2 || disp === 5;
      this.keep = wanted(path) && (CFG.reads || writes);
      if (this.keep) this.f = { path: path, access: hex(access), write: writes, share: hex(a[2].toInt32()), disposition: DISP[disp] || disp, flags: hex(a[5].toInt32()) };
    },
    onLeave: function (r) {
      if (!this.keep) return;
      this.f.ok = !r.equals(ptr('-1'));
      var le = lastError(this);
      if (!this.f.ok) this.f.error = le;
      else if (le === 183) this.f.existed = true; /* ERROR_ALREADY_EXISTS on OPEN_ALWAYS / CREATE_ALWAYS */
      emit('CreateFileW', this.f, this);
    } } },
  { name: 'MoveFileExW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: moveSpec('MoveFileExW', 0, 1, 2) },
  { name: 'MoveFileWithProgressW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: moveSpec('MoveFileWithProgressW', 0, 1, 4) },
  { name: 'ReplaceFileW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) {
      enterMove(this);
      this.f = { replaced: wstr(a[0]), replacement: wstr(a[1]), backup: wstr(a[2]), flags: hex(a[3].toInt32()) };
      this.keep = this.outer && (wanted(this.f.replaced) || wanted(this.f.replacement));
    },
    onLeave: function (r) {
      leaveMove();
      if (!this.keep) return;
      this.f.ok = r.toInt32() !== 0; if (!this.f.ok) this.f.error = lastError(this);
      emit('ReplaceFileW', this.f, this);
    } } },
  { name: 'DeleteFileW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) { this.f = { path: wstr(a[0]) }; this.keep = wanted(this.f.path); },
    onLeave: function (r) {
      if (!this.keep) return;
      this.f.ok = r.toInt32() !== 0; if (!this.f.ok) this.f.error = lastError(this);
      emit('DeleteFileW', this.f, this);
    } } },
  { name: 'RemoveDirectoryW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) { this.f = { path: wstr(a[0]) }; this.keep = wanted(this.f.path); },
    onLeave: function (r) {
      if (!this.keep) return;
      this.f.ok = r.toInt32() !== 0; if (!this.f.ok) this.f.error = lastError(this);
      emit('RemoveDirectoryW', this.f, this);
    } } },
  { name: 'GetPrivateProfileStringW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) {
      this.f = { file: wstr(a[5]), section: wstr(a[0]), key: wstr(a[1]), default: wstr(a[2]) };
      this.buf = a[3]; this.keep = wanted(this.f.file);
    },
    onLeave: function (r) {
      if (!this.keep) return;
      var n = r.toInt32() >>> 0;
      try { this.f.value = this.buf.isNull() ? null : this.buf.readUtf16String(n); } catch (e) { this.f.value = '<unreadable>'; }
      emit('GetPrivateProfileStringW', this.f, this);
    } } },
  { name: 'GetPrivateProfileIntW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) {
      this.f = { file: wstr(a[3]), section: wstr(a[0]), key: wstr(a[1]), default: a[2].toInt32() };
      this.keep = wanted(this.f.file);
    },
    onLeave: function (r) { if (this.keep) { this.f.value = r.toInt32(); emit('GetPrivateProfileIntW', this.f, this); } } } },
  { name: 'WritePrivateProfileStringW', mods: ['KernelBase.dll', 'kernel32.dll'], spec: {
    onEnter: function (a) {
      this.f = { file: wstr(a[3]), section: wstr(a[0]), key: wstr(a[1]), value: wstr(a[2]) };
      this.keep = wanted(this.f.file);
    },
    onLeave: function (r) {
      if (!this.keep) return;
      this.f.ok = r.toInt32() !== 0; if (!this.f.ok) this.f.error = lastError(this);
      emit('WritePrivateProfileStringW', this.f, this);
    } } },
  { name: 'RegSetValueExW', mods: ['KernelBase.dll', 'advapi32.dll'], spec: {
    onEnter: function (a) {
      var type = a[3].toInt32() >>> 0, cb = a[5].toInt32() >>> 0;
      this.f = { key: keyPath(a[0]), value_name: wstr(a[1]), type: REG_TYPES[type] || type, size: cb, data: regData(type, a[4], cb) };
    },
    onLeave: function (r) { this.f.status = r.toInt32(); emit('RegSetValueExW', this.f, this); } } }
];

function installPending() {
  var left = 0;
  HOOKS.forEach(function (h) {
    if (installed[h.name]) return;
    var e = findExport(h.mods, h.name);
    if (e === null) { left++; return; }
    try {
      Interceptor.attach(e.addr, h.spec);
      installed[h.name] = e.module;
      emit('hook_installed', { target: h.name, module: e.module }, null);
    } catch (err) {
      installed[h.name] = 'error';
      emit('hook_error', { target: h.name, error: String(err) }, null);
    }
  });
  return left;
}

rpc.exports = {
  /* frida CLI passes -P JSON here. */
  init: function (stage, params) {
    if (params) for (var k in params) CFG[k] = params[k];
    includeRx = CFG.include ? new RegExp(CFG.include, 'i') : null;
    excludeRx = CFG.exclude ? new RegExp(CFG.exclude, 'i') : null;
  },
  pending: function () { return HOOKS.filter(function (h) { return !installed[h.name]; }).map(function (h) { return h.name; }); }
};
emit('trace_start', { script: 'trace_files', process: Process.enumerateModules()[0].path, arch: Process.arch, frida: Frida.version }, null);
/* Hooks whose module is not loaded yet are retried every second for a minute. */
(function retry(n) { if (installPending() > 0 && n > 0) setTimeout(function () { retry(n - 1); }, 1000); })(60);
