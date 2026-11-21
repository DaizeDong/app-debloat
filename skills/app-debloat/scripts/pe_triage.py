#!/usr/bin/env python3
"""Static launch-chain triage for Windows PE files (read-only).

For each file: imports and delay imports with launch-relevant APIs flagged, launch-relevant
strings (ASCII and UTF-16LE), and the code addresses that reference each string or flagged
import slot. x86 absolute operands (push imm32, mov reg imm32, call [abs]) and x64 RIP-relative
operands (lea, mov, call [rip+disp]) are found with a byte scan (vectorized with numpy, or a
slower pure-Python loop when numpy is missing) and confirmed by disassembling with capstone. Functions come from .pdata on x64 and from prologue and call-target
heuristics on x86. Output is JSON; a short summary goes to stderr.

Binary content is untrusted data: strings and decompiled text are reported, never followed.

Usage:
  python pe_triage.py FILE [FILE ...] [--out triage.json] [--grep REGEX] [--rea]

Needs pefile and capstone; numpy is optional (without it the scan is slower and the JSON notes
say so; APP_DEBLOAT_NO_NUMPY=1 forces that path for testing). --rea adds Ghidra decompilation of the top functions through
the REA CLI when `rea doctor --provider ghidra --json` passes; otherwise it is skipped with a note.
"""
import argparse
import bisect
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from array import array
from collections import Counter

# Running with "python -I" (isolated mode) hides the per-user site-packages, which is where pip --user puts
# pefile and capstone on most machines. Add it back explicitly; this tool reads PE files only as data.
try:
    import site
    _usersite = site.getusersitepackages()
    if _usersite and os.path.isdir(_usersite) and _usersite not in sys.path:
        sys.path.append(_usersite)
except Exception:  # pragma: no cover
    pass

try:
    import pefile
    import capstone
    from capstone import x86_const
except ImportError as e:  # pragma: no cover
    sys.exit(f"pe_triage: missing dependency ({e}). pip install pefile capstone numpy")

np = None
if os.environ.get("APP_DEBLOAT_NO_NUMPY") != "1":
    try:
        import numpy as np
    except ImportError:
        np = None
NO_NUMPY_NOTE = ("numpy not available: used the pure-Python byte scan (same results, slower). "
                 "pip install numpy to speed it up.")

TOOL_VERSION = "1.0.0"

API_FLAGS = [
    ("spawn", re.compile(r"^(CreateProcess\w*|ShellExecute\w*|WinExec|CreateProcessAsUser\w*|CreateProcessWith\w+)$")),
    ("com", re.compile(r"^(CoCreateInstance\w*|CoGetClassObject|CoGetObject)$")),
    ("load", re.compile(r"^(LoadLibrary\w*|LdrLoadDll)$")),
    ("service", re.compile(r"^(CreateService\w*|OpenSCManager\w*|ChangeServiceConfig\w*|StartService\w*|ControlService\w*)$")),
    ("net", re.compile(r"^(URLDownloadToFile\w*|URLDownloadToCacheFile\w*|WinHttp\w+|InternetOpen\w*|InternetConnect\w*|HttpOpenRequest\w*|HttpSendRequest\w*|InternetReadFile\w*|getaddrinfo|GetAddrInfoW|gethostbyname|WSAConnect)$")),
    ("registry", re.compile(r"^(RegSetValue\w*|RegSetKeyValue\w*|RegCreateKey\w*)$")),
    ("shm", re.compile(r"^(CreateFileMapping\w*|OpenFileMapping\w*)$")),
    ("dynamic", re.compile(r"^(GetProcAddress|LdrGetProcedureAddress)$")),
]
API_WEIGHT = {"spawn": 5, "service": 4, "net": 3, "com": 2, "load": 2, "shm": 2, "registry": 1, "dynamic": 0}

STR_CATS = [
    ("url", re.compile(r"https?://[^\s\"'<>]{3,}", re.I)),
    ("exe", re.compile(r"(?<![\w.])[\w\-. ]{1,64}\.(?:exe|dll|ime|sys)\b", re.I)),
    ("switch", re.compile(r"(?:^|\s)(?:--[a-z][\w-]{1,40}(?:=\S*)?|-(?:daemon|silent|auto|install|update|repair|embedding|background|hide|tray|service)\b|/(?:silent|quiet|install|update|repair|daemon|s)\b)", re.I)),
    ("registry", re.compile(r"HKEY_\w+|\bHK(?:LM|CU|CR)\\|\bSOFTWARE\\|\\CurrentVersion\\|Image File Execution Options|\\Shell Extensions\\|\bCLSID\\", re.I)),
    ("task", re.compile(r"Schedule\.Service|\bschtasks\b|\\Microsoft\\Windows\\Task|TaskScheduler", re.I)),
    ("config", re.compile(r"[\w\-.]{1,64}\.(?:ini|json|xml|ya?ml|cfg|conf|cupf|plist)\b", re.I)),
    ("host", re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|cn|net|org|io|cc|top|info|xyz|co|me|tv)\b", re.I)),
    ("guid", re.compile(r"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}", re.I)),
]
STR_WEIGHT = {"grep": 4, "exe": 3, "switch": 2, "url": 2, "task": 3, "registry": 1, "config": 1, "host": 1, "guid": 1, "api_name": 2}
API_NAME_RX = re.compile(r"^(?:" + "|".join(rx.pattern.strip("^$") for c, rx in API_FLAGS if c != "dynamic") + r")$")
# CLSID_TaskScheduler {0F87369F-A4E5-4CFC-BD3E-73E6154572DD} as a binary GUID: ITaskService users embed it.
TASK_CLSID_BIN = bytes.fromhex("9f36870fe5a4fc4cbd3e73e6154572dd")

SCN_EXEC = 0x20000000
SCN_CODE = 0x00000020


def api_category(name):
    if not name:
        return None
    for cat, rx in API_FLAGS:
        if rx.match(name):
            return cat
    return None


def string_categories(s, grep):
    cats = [c for c, rx in STR_CATS if rx.search(s)]
    if grep and grep.search(s):
        cats.insert(0, "grep")
    if API_NAME_RX.match(s):
        cats.append("api_name")
    return cats


class Image:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        self.pe = pefile.PE(data=self.raw, fast_load=True)
        self.pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
        ])
        m = self.pe.FILE_HEADER.Machine
        self.is64 = m == 0x8664
        if m not in (0x14C, 0x8664):
            raise ValueError(f"unsupported machine 0x{m:x} (x86 and x64 only)")
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.is64 else capstone.CS_MODE_32)
        self.cs.detail = True
        self.sections = []
        for s in self.pe.sections:
            data = s.get_data()
            self.sections.append({
                "name": s.Name.rstrip(b"\0").decode("latin-1"), "rva": s.VirtualAddress, "data": data,
                "vsize": s.Misc_VirtualSize, "exec": bool(s.Characteristics & (SCN_EXEC | SCN_CODE)),
                "raw_off": s.PointerToRawData,
            })
        self.code = [s for s in self.sections if s["exec"] and s["data"]]

    def managed(self):
        d = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return d.VirtualAddress != 0 and d.Size != 0


def collect_imports(img):
    out, slots = [], {}
    for attr, kind in (("DIRECTORY_ENTRY_IMPORT", "import"), ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay")):
        for entry in getattr(img.pe, attr, []) or []:
            dll = entry.dll.decode("latin-1") if entry.dll else "?"
            names = []
            for imp in entry.imports:
                name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
                names.append(name)
                cat = api_category(name)
                if cat and imp.address:
                    slots[imp.address] = {"dll": dll, "name": name, "kind": kind, "category": cat,
                                          "iat_rva": imp.address - img.base}
            out.append({"dll": dll, "kind": kind, "count": len(names), "names": names})
    return out, slots


def extract_strings(img, minlen, grep, cap):
    found, seen = [], set()
    rx_a = re.compile(rb"[\x20-\x7e]{%d,}" % minlen)
    rx_w = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen)
    for s in img.sections:
        for enc, rx in (("ascii", rx_a), ("utf16", rx_w)):
            for m in rx.finditer(s["data"]):
                raw = m.group()
                text = raw.decode("latin-1") if enc == "ascii" else raw.decode("utf-16le", "replace")
                cats = string_categories(text, grep)
                if not cats:
                    continue
                rva = s["rva"] + m.start()
                if (rva, enc) in seen:
                    continue
                seen.add((rva, enc))
                found.append({"value": text[:400], "encoding": enc, "rva": rva, "section": s["name"],
                              "categories": cats, "xrefs": [], "data_refs": []})
                if len(found) >= cap:
                    return found, True
    return found, False


def _dwords(data, off, signed):
    """Little-endian 32-bit values at byte offsets off, off+4, ... (pure-Python path)."""
    cnt = (len(data) - off) // 4
    a = array("i" if signed else "I")
    a.frombytes(bytes(data[off:off + cnt * 4]))
    if sys.byteorder != "little":
        a.byteswap()
    return a


def _rel32_sites(data, opcodes):
    """(position, signed rel32) for each opcode byte followed by 4 bytes (pure-Python path)."""
    pat = re.compile(b"[" + b"".join(re.escape(bytes([o])) for o in opcodes) + b"](?=[\x00-\xff]{4})")
    unpack = struct.Struct("<i").unpack_from
    return [(m.start(), unpack(data, m.start() + 1)[0]) for m in pat.finditer(data)]


def candidate_positions(data, targets, is64, sec_rva, base):
    """Byte positions whose 4-byte operand may encode one of the target VAs."""
    if len(data) < 8 or not len(targets):
        return []
    if np is None:
        hits = []
        if is64:
            # t = sec_rva + pos + 4 + extra + disp must be a target RVA, for any extra in (0, 1, 2, 4)
            want = {t - base - e for t in targets for e in (0, 1, 2, 4)}
            for off in range(4):
                adj = sec_rva + off + 4
                for k, d in enumerate(_dwords(data, off, True)):
                    if adj + 4 * k + d in want:
                        hits.append(off + 4 * k)
        else:
            want = set(targets)
            for off in range(4):
                for k, v in enumerate(_dwords(data, off, False)):
                    if v in want:
                        hits.append(off + 4 * k)
        return sorted(set(hits))
    buf = np.frombuffer(data, dtype=np.uint8)
    n = len(buf) - 3
    v = (buf[:n].astype(np.int64) | (buf[1:n + 1].astype(np.int64) << 8) |
         (buf[2:n + 2].astype(np.int64) << 16) | (buf[3:n + 3].astype(np.int64) << 24))
    pos = np.arange(n, dtype=np.int64)
    hits = set()
    if is64:
        disp = np.where(v >= 2**31, v - 2**32, v)
        rva_targets = np.array(sorted(t - base for t in targets), dtype=np.int64)
        for extra in (0, 1, 2, 4):          # immediate bytes that may follow the displacement
            t = sec_rva + pos + 4 + extra + disp
            hits.update(np.nonzero(np.isin(t, rva_targets))[0].tolist())
    else:
        va_targets = np.array(sorted(targets), dtype=np.int64)
        hits.update(np.nonzero(np.isin(v, va_targets))[0].tolist())
    return sorted(hits)


PREFERRED = {"call", "jmp", "push", "lea", "mov", "cmp", "movzx", "movsx", "test"}


def confirm(img, sec, pos, targets, mem_only=()):
    """Disassemble backwards from an operand position; return (insn_rva, text, target_va) or None.

    Several start offsets can decode to an instruction that covers the operand (FF 15 xx read from
    one byte later is 'adc eax, imm32'), so every candidate is scored and the most plausible wins.
    """
    data, sec_va = sec["data"], img.base + sec["rva"]
    best = None
    for back in range(1, 8):
        start = pos - back
        if start < 0:
            break
        for insn in img.cs.disasm(data[start:start + 16], sec_va + start, count=1):
            if insn.address + insn.size < sec_va + pos + 4:
                continue
            for op in insn.operands:
                val, is_mem = None, False
                if op.type == x86_const.X86_OP_IMM:
                    val = op.imm & 0xFFFFFFFFFFFFFFFF
                elif op.type == x86_const.X86_OP_MEM:
                    is_mem = True
                    if img.is64 and op.mem.base == x86_const.X86_REG_RIP:
                        val = insn.address + insn.size + op.mem.disp
                    elif not img.is64 and op.mem.base == 0 and op.mem.index == 0:
                        val = op.mem.disp & 0xFFFFFFFF
                if val is None or val not in targets or (val in mem_only and not is_mem):
                    continue
                score = (2 if insn.mnemonic in PREFERRED else 0) + (1 if is_mem else 0)
                if best is None or score > best[0]:
                    best = (score, insn.address - img.base, f"{insn.mnemonic} {insn.op_str}", val)
    return best[1:] if best else None


def rel32_callers(img, dest_rvas):
    """E8/E9 rel32 call or jmp sites that land on any of dest_rvas (used to see through import thunks)."""
    out = {}
    if not dest_rvas:
        return out
    if np is None:
        want = set(dest_rvas)
        for sec in img.code:
            if len(sec["data"]) < 6:
                continue
            for i, rel in _rel32_sites(sec["data"], (0xE8, 0xE9)):
                dest = sec["rva"] + i + 5 + rel
                if dest in want:
                    out.setdefault(int(dest), []).append(int(sec["rva"] + i))
        return out
    want = np.array(sorted(dest_rvas), dtype=np.int64)
    for sec in img.code:
        buf = np.frombuffer(sec["data"], dtype=np.uint8)
        if len(buf) < 6:
            continue
        idx = np.nonzero((buf[:-4] == 0xE8) | (buf[:-4] == 0xE9))[0].astype(np.int64)
        rel = (buf[idx + 1].astype(np.int64) | (buf[idx + 2].astype(np.int64) << 8) |
               (buf[idx + 3].astype(np.int64) << 16) | (buf[idx + 4].astype(np.int64) << 24))
        rel = np.where(rel >= 2**31, rel - 2**32, rel)
        dest = sec["rva"] + idx + 5 + rel
        for i in np.nonzero(np.isin(dest, want))[0].tolist():
            out.setdefault(int(dest[i]), []).append(int(sec["rva"] + idx[i]))
    return out


def function_index(img):
    """Sorted function starts plus the source of that knowledge."""
    entries = getattr(img.pe, "DIRECTORY_ENTRY_EXCEPTION", None)
    if img.is64 and entries:
        starts, ends = [], {}
        for e in entries:
            st = e.struct.BeginAddress
            ui = getattr(e, "unwindinfo", None)
            fe = getattr(ui, "FunctionEntry", None) if ui is not None else None
            primary = getattr(fe, "BeginAddress", None) if fe is not None else None
            starts.append((st, primary or st))
            ends[st] = e.struct.EndAddress
        starts.sort()
        return {"source": "pdata", "starts": [s for s, _ in starts], "primary": dict(starts), "ends": ends}
    starts = set()
    for sec in img.code:
        d = sec["data"]
        for pat in (b"\x55\x8b\xec", b"\x8b\xff\x55\x8b\xec"):
            for m in re.finditer(re.escape(pat), d):
                starts.add(sec["rva"] + m.start())
        if np is None:
            if len(d) > 6:
                lo, hi = sec["rva"], sec["rva"] + len(d)
                cnt = Counter(sec["rva"] + i + 5 + rel for i, rel in _rel32_sites(d, (0xE8,)))
                starts.update(t for t, c in cnt.items() if c >= 2 and lo <= t < hi)
            continue
        buf = np.frombuffer(d, dtype=np.uint8)
        if len(buf) > 6:
            idx = np.nonzero(buf[:-4] == 0xE8)[0].astype(np.int64)
            rel = (buf[idx + 1].astype(np.int64) | (buf[idx + 2].astype(np.int64) << 8) |
                   (buf[idx + 3].astype(np.int64) << 16) | (buf[idx + 4].astype(np.int64) << 24))
            rel = np.where(rel >= 2**31, rel - 2**32, rel)
            dest = sec["rva"] + idx + 5 + rel
            inside = dest[(dest >= sec["rva"]) & (dest < sec["rva"] + len(d))]
            vals, counts = np.unique(inside, return_counts=True)
            starts.update(vals[counts >= 2].tolist())
    return {"source": "heuristic", "starts": sorted(int(s) for s in starts), "primary": {}, "ends": {}}


def func_of(fidx, rva):
    i = bisect.bisect_right(fidx["starts"], rva) - 1
    if i < 0:
        return None
    st = fidx["starts"][i]
    if fidx["source"] == "pdata" and rva >= fidx["ends"].get(st, rva + 1):
        return None
    return fidx["primary"].get(st, st)


def triage(path, args, grep):
    img = Image(path)
    res = {
        "path": path, "sha256": hashlib.sha256(img.raw).hexdigest(), "size": len(img.raw),
        "machine": "x64" if img.is64 else "x86", "image_base": hex(img.base),
        "is_dll": bool(img.pe.FILE_HEADER.Characteristics & 0x2000), "managed": img.managed(),
        "sections": [{"name": s["name"], "rva": hex(s["rva"]), "vsize": s["vsize"], "exec": s["exec"]} for s in img.sections],
        "notes": [],
    }
    if res["managed"]:
        res["notes"].append(".NET image: native xrefs are meaningless; use a managed decompiler or REA managed inspection.")
    imports, slots = collect_imports(img)
    res["imports"] = imports
    strings, capped = extract_strings(img, args.min_len, grep, args.max_strings)
    if capped:
        res["notes"].append(f"string cap {args.max_strings} reached; raise --max-strings or narrow with --grep.")

    targets = {}
    for s in strings:
        targets.setdefault(img.base + s["rva"], ("str", s))
    for va, sl in slots.items():
        sl["refs"] = []
        targets[va] = ("imp", sl)
    tset = set(targets)
    imp_vas = set(slots)

    # code xrefs
    for sec in img.code:
        for pos in candidate_positions(sec["data"], list(tset), img.is64, sec["rva"], img.base):
            c = confirm(img, sec, pos, tset, imp_vas)
            if not c:
                continue
            irva, text, tva = c
            kind, obj = targets[tva]
            lst = obj["xrefs"] if kind == "str" else obj["refs"]
            if all(x["rva"] != irva for x in lst) and len(lst) < args.max_xrefs:
                lst.append({"rva": irva, "insn": text})
    # data refs (pointer tables in non-code sections): one hop only
    ptr = "<u8" if img.is64 else "<u4"
    width = 8 if img.is64 else 4
    by_va = {img.base + s["rva"]: s for s in strings}
    if np is not None:
        str_vas = np.array(sorted(by_va), dtype=np.uint64)
    for sec in img.sections:
        if sec["exec"] or len(sec["data"]) < width or not by_va:
            continue
        d = sec["data"][: len(sec["data"]) // width * width]
        if np is None:
            vals = array("Q" if img.is64 else "I")
            vals.frombytes(bytes(d))
            if sys.byteorder != "little":
                vals.byteswap()
            idxs = [i for i, v in enumerate(vals) if v in by_va][:5000]
        else:
            vals = np.frombuffer(d, dtype=ptr).astype(np.uint64)
            idxs = np.nonzero(np.isin(vals, str_vas))[0].tolist()[:5000]
        for i in idxs:
            s = by_va[int(vals[i])]
            if len(s["data_refs"]) < args.max_xrefs:
                s["data_refs"].append(sec["rva"] + i * width)

    # second hop: code that reads a pointer table holding string addresses (entry or table base)
    lo, hi = img.base, img.base + img.pe.OPTIONAL_HEADER.SizeOfImage
    hop = {}
    for st in strings:
        for r in st["data_refs"]:
            sec = next((x for x in img.sections if x["rva"] <= r < x["rva"] + len(x["data"])), None)
            if sec is None:
                continue
            base_rva, steps = r, 0
            while base_rva - width >= sec["rva"] and steps < 256:
                off = base_rva - width - sec["rva"]
                val = int.from_bytes(sec["data"][off:off + width], "little")
                if not (lo <= val < hi):
                    break
                base_rva -= width
                steps += 1
            for t in {r, base_rva}:
                hop.setdefault(img.base + t, []).append((st, t == base_rva and t != r))
    if hop:
        hset = set(hop)
        for sec in img.code:
            for pos in candidate_positions(sec["data"], list(hset), img.is64, sec["rva"], img.base):
                c = confirm(img, sec, pos, hset)
                if not c:
                    continue
                irva, text, tva = c
                for st, via_base in hop[tva]:
                    lst = st.setdefault("table_xrefs", [])
                    if all(x["rva"] != irva for x in lst) and len(lst) < args.max_xrefs:
                        lst.append({"rva": irva, "insn": text, "table": hex(tva), "via_table_base": via_base})

    # thunks: a jmp [iat] is an import stub; its callers are the real call sites
    thunks = {}
    for sl in slots.values():
        for r in sl["refs"]:
            if r["insn"].startswith("jmp"):
                thunks[r["rva"]] = sl
    for dest, callers in rel32_callers(img, set(thunks)).items():
        sl = thunks[dest]
        for c in callers[: args.max_xrefs]:
            sl["refs"].append({"rva": c, "insn": f"call thunk 0x{dest:x}"})

    fidx = function_index(img)
    res["function_source"] = fidx["source"]
    funcs = {}

    def fn(rva):
        f = func_of(fidx, rva)
        key = f if f is not None else -1
        return funcs.setdefault(key, {"start_rva": f, "apis": {}, "strings": [], "score": 0})

    flagged = []
    for sl in slots.values():
        for r in sl["refs"]:
            r["func"] = func_of(fidx, r["rva"])
            if not r["insn"].startswith("jmp"):
                fn(r["rva"])["apis"].setdefault(sl["name"], sl["category"])
        flagged.append({"name": sl["name"], "dll": sl["dll"], "kind": sl["kind"], "category": sl["category"],
                        "iat_rva": sl["iat_rva"], "call_sites": [{"rva": r["rva"], "insn": r["insn"], "func": r.get("func")} for r in sl["refs"]]})
    flagged.sort(key=lambda x: (-API_WEIGHT.get(x["category"], 0), x["name"]))
    res["flagged_imports"] = flagged
    if TASK_CLSID_BIN in img.raw:
        res["notes"].append("Embeds CLSID_TaskScheduler as a binary GUID: likely an ITaskService (scheduled task) user.")
        res["task_scheduler_clsid"] = True
    flagged_names = {f["name"] for f in flagged}
    if "GetProcAddress" in flagged_names:
        dyn = sorted({s["value"] for s in strings if "api_name" in s["categories"]})
        if dyn:
            res["notes"].append("Resolves APIs at run time; flagged API names found as strings: " + ", ".join(dyn[:20]))

    for s in strings:
        for x in s.get("table_xrefs", []):
            x["func"] = func_of(fidx, x["rva"])
        for x in s["xrefs"]:
            x["func"] = func_of(fidx, x["rva"])
            f = fn(x["rva"])
            if len(f["strings"]) < 40 and all(v["value"] != s["value"][:160] for v in f["strings"]):
                f["strings"].append({"value": s["value"][:160], "categories": s["categories"], "rva": x["rva"]})
    for f in funcs.values():
        # APIs dominate: a function that spawns or installs something outranks one that only logs names.
        api = sum(API_WEIGHT.get(c, 0) for c in set(f["apis"].values()))
        strs = sum(max(STR_WEIGHT.get(c, 0) for c in st["categories"]) for st in f["strings"])
        f["score"] = 2 * api + min(strs, 12) + (4 if api and strs else 0)
    ranked = sorted((f for k, f in funcs.items() if k != -1), key=lambda f: -f["score"])
    top = ranked[: args.top]
    # Spawn helpers usually take the target as an argument, so the launch string sits one call up.
    wrappers = [f for f in top if set(f["apis"].values()) & {"spawn", "service", "net"}]
    callers = rel32_callers(img, {f["start_rva"] for f in wrappers})
    for f in wrappers:
        seen = []
        for site in callers.get(f["start_rva"], [])[: args.max_xrefs]:
            cf = func_of(fidx, site)
            if cf is None or any(c["func"] == cf for c in seen):
                continue
            cs = funcs.get(cf, {}).get("strings", [])
            seen.append({"func": cf, "site": site, "strings": [s["value"][:120] for s in cs[:8]]})
        f["callers"] = seen
    res["top_functions"] = [dict(f, start_va=hex(img.base + f["start_rva"])) for f in top]
    res["strings"] = [s for s in strings if s["xrefs"] or s["data_refs"] or "grep" in s["categories"] or not args.only_referenced]
    res["counts"] = {
        "imports": sum(i["count"] for i in imports), "flagged_imports": len(flagged),
        "flagged_with_sites": sum(1 for f in flagged if f["call_sites"]),
        "strings": len(strings), "strings_with_xrefs": sum(1 for s in strings if s["xrefs"]),
        "strings_with_data_refs": sum(1 for s in strings if s["data_refs"]),
        "strings_with_table_xrefs": sum(1 for s in strings if s.get("table_xrefs")), "functions": len(fidx["starts"]),
    }
    return hexify(res), img


ADDR_KEYS = {"rva", "func", "start_rva", "iat_rva", "site"}


def hexify(o):
    """Render every address field as a hex string so it can be pasted into a ledger anchor."""
    if isinstance(o, dict):
        return {k: (hex(v) if k in ADDR_KEYS and isinstance(v, int) and not isinstance(v, bool) else
                    [hex(x) for x in v] if k == "data_refs" else hexify(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [hexify(v) for v in o]
    return o


def rea_backend(timeout):
    exe = shutil.which("rea")
    if not exe:
        return None, "rea CLI not on PATH; decompilation skipped."
    try:
        p = subprocess.run([exe, "doctor", "--provider", "ghidra", "--json"], capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return None, f"rea doctor failed to run ({e}); decompilation skipped."
    if p.returncode != 0:
        return None, f"rea doctor --provider ghidra exited {p.returncode}; decompilation skipped."
    return exe, None


def rea_decompile(exe, path, va, timeout):
    try:
        p = subprocess.run([exe, "decompile", path, hex(va), "--provider", "ghidra", "--json"], capture_output=True,
                           text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s"}
    if p.returncode != 0:
        return {"error": f"exit {p.returncode}: {p.stderr.strip()[:300]}"}
    text = p.stdout
    try:
        doc = json.loads(text)
        found = []

        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if isinstance(v, str) and k.lower() in ("pseudocode", "decompiled", "c", "code", "source", "text"):
                        found.append(v)
                    else:
                        walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(doc)
        text = max(found, key=len) if found else text
    except ValueError:
        pass
    return {"untrusted_snippet": text[:4000]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out", help="JSON output path (default: stdout)")
    ap.add_argument("--grep", action="append", default=[], help="extra regex; matching strings are always kept and ranked high")
    ap.add_argument("--min-len", type=int, default=5)
    ap.add_argument("--max-strings", type=int, default=6000)
    ap.add_argument("--max-xrefs", type=int, default=24)
    ap.add_argument("--top", type=int, default=25, help="functions to rank")
    ap.add_argument("--only-referenced", action="store_true", help="drop strings with no code or data reference")
    ap.add_argument("--rea", action="store_true", help="decompile top functions through the REA CLI if available")
    ap.add_argument("--rea-top", type=int, default=3)
    ap.add_argument("--rea-timeout", type=int, default=900, help="seconds per REA call (cold Ghidra import is slow)")
    args = ap.parse_args()
    grep = re.compile("|".join(f"(?:{g})" for g in args.grep), re.I) if args.grep else None

    report = {"schema": "app-debloat.pe-triage/1", "tool_version": TOOL_VERSION, "files": [], "notes": []}
    if np is None:
        report["notes"].append(NO_NUMPY_NOTE)
        print(f"[pe_triage] {NO_NUMPY_NOTE}", file=sys.stderr)
    rea_exe = None
    if args.rea:
        rea_exe, note = rea_backend(min(args.rea_timeout, 180))
        if note:
            report["notes"].append(note)
    for path in args.files:
        try:
            res, img = triage(path, args, grep)
        except Exception as e:  # noqa: BLE001
            report["files"].append({"path": path, "error": f"{type(e).__name__}: {e}"})
            print(f"[pe_triage] {path}: {e}", file=sys.stderr)
            continue
        if rea_exe:
            for f in res["top_functions"][: args.rea_top]:
                f["rea"] = rea_decompile(rea_exe, path, int(f["start_va"], 16), args.rea_timeout)
        report["files"].append(res)
        c = res["counts"]
        print(f"[pe_triage] {path} ({res['machine']}, funcs via {res['function_source']}): "
              f"{c['flagged_imports']} flagged imports ({c['flagged_with_sites']} with call sites), "
              f"{c['strings']} strings ({c['strings_with_xrefs']} with code xrefs)", file=sys.stderr)
        for f in res["flagged_imports"]:
            if f["category"] in ("spawn", "service"):
                funcs = sorted({s["func"] for s in f["call_sites"] if s.get("func") is not None})
                print(f"    {f['name']}: {len(f['call_sites'])} sites in {len(funcs)} functions", file=sys.stderr)
        for f in res["top_functions"][:5]:
            vals = ", ".join(sorted({s["value"][:40] for s in f["strings"]})[:4])
            print(f"    top {f['start_va']} score {f['score']}: apis={sorted(f['apis'])[:5]} strings=[{vals}]", file=sys.stderr)
    text = json.dumps(report, indent=1, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
