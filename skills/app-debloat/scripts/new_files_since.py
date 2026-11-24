#!/usr/bin/env python3
"""List executables, installers and archives that appeared or changed under common drop folders since a time.

Read-only: it lists directories and reads file metadata from the directory listing, nothing else
(with --sniff it also reads the first 8 bytes of new files whose extension does not match). It answers
the P3 checkpoint "does any vendor process write outside its own roots": run it after a launch, an
idle period or a triggered update, with --since set to the time before that window.

A recursive Get-ChildItem over AppData and ProgramData can run for many minutes; this walk uses
os.scandir, takes metadata from the listing itself, and never descends into junctions, symbolic
links or other reparse points (OneDrive and other cloud folders included; they are counted, not
walked). Known caches are skipped by folder name: Chromium and Electron caches (Code Cache,
GPUCache, Cache next to Code Cache or Local Storage, and similar), Firefox cache2, INetCache,
INetCookies, WebCache, and the AC folder of each %LOCALAPPDATA%\\Packages\\<package>.

Usage (run Python isolated, so nothing in the current folder is imported):
  python -I new_files_since.py --since 2030-01-01T09:30 --out <private dir>\\new-files.json --summary
  python -I new_files_since.py --since 2030-01-01T09:30Z --root "%LOCALAPPDATA%\\Temp" --min-size 100000 --summary

Options:
  --since TIME     ISO 8601 time (local time when it has no offset). A file is listed when its
                   creation or last-write time is at or after it.
  --root DIR       a folder to walk (repeatable, %VAR% allowed). Default: %LOCALAPPDATA%,
                   %APPDATA%, %ProgramData%, and the Downloads, Desktop and Documents known folders.
                   A root inside another root is walked once.
  --min-size N     only files of at least N bytes.
  --ext LIST       comma-separated extensions that replace the built-in executable and archive list.
  --all            list every new file, whatever its extension.
  --sniff          also list new files whose first bytes are a PE, ZIP, 7z, CAB, RAR or MSI (OLE)
                   header, whatever their extension (updaters often download to *.tmp).
  --skip-dir NAME  another folder name to skip (repeatable, exact, case-insensitive).
  --no-default-skips  walk the known caches too.
  --out FILE       write the JSON result to FILE. Real-run DATA: the private companion only.
  --summary        print a readable summary to stdout (never mixed with JSON).
  --max-lines N    files listed in the summary (default 30, newest first).
  --keep-paths     keep the literal user profile path and user name (default: %USERPROFILE%, %USERNAME%).
Without --out and --summary the JSON goes to stdout. Exit code 0 unless the arguments are wrong;
folders that could not be read are counted under errors, so "nothing new" and "not walked" differ.
"""
import argparse
import ctypes
import json
import os
import stat
import sys
import time
from datetime import datetime

TOOL_VERSION = "1.0.0"

TYPES = {
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".com", ".efi",
    ".msi", ".msp", ".msu", ".msix", ".msixbundle", ".appx", ".appxbundle",
    ".zip", ".7z", ".rar", ".cab", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".zst", ".lzma",
    ".asar", ".nupkg", ".crx",
    ".bat", ".cmd", ".ps1", ".vbs",
}
# A staged copy keeps its real extension in front of one of these (app.asar.new, setup.exe.tmp).
STAGE_SUFFIX = {".new", ".old", ".tmp", ".bak", ".part", ".partial", ".crdownload", ".download", ".dl"}
MAGIC = [
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"MSCF", "cab"),
    (b"Rar!", "rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
]
# Folder names that only hold browser or system caches. "cache" alone is skipped only next to a
# Chromium or Electron profile marker, because vendors also name their own download folders Cache.
ALWAYS_SKIP = {"code cache", "gpucache", "dawncache", "dawngraphitecache", "dawnwebgpucache", "grshadercache",
               "graphitedawncache", "shadercache", "cachestorage", "scriptcache", "cache_data", "cache2",
               "inetcache", "inetcookies", "webcache"}
PROFILE_MARKERS = {"code cache", "gpucache", "local storage", "session storage", "network", "preferences"}
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
REPARSE_TAGS = {0xA0000003: "junction", 0xA000000C: "symlink", 0x8000001B: "appexeclink"}
KNOWN_FOLDERS = {  # FOLDERID values from KnownFolders.h
    "Downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "Desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "Documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
}
SAMPLE = 50  # examples kept per skip or error list


def known_folder(name):
    """Path of a known folder (follows folder redirection), or the %USERPROFILE% default."""
    try:
        class GUID(ctypes.Structure):
            _fields_ = [("d1", ctypes.c_uint32), ("d2", ctypes.c_uint16), ("d3", ctypes.c_uint16), ("d4", ctypes.c_ubyte * 8)]
        g = GUID()
        ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(KNOWN_FOLDERS[name]), ctypes.byref(g))
        p = ctypes.c_wchar_p()
        ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(p))
        try:
            if p.value:
                return p.value
        finally:
            ctypes.windll.ole32.CoTaskMemFree(p)
    except (AttributeError, OSError):
        pass
    prof = os.environ.get("USERPROFILE")
    return os.path.join(prof, name) if prof else None


def default_roots():
    out = [os.environ.get(v) for v in ("LOCALAPPDATA", "APPDATA", "ProgramData")]
    out += [known_folder(n) for n in ("Downloads", "Desktop", "Documents")]
    return [r for r in out if r]


def norm_root(r):
    return os.path.normpath(os.path.expandvars(r.strip().strip('"')))


def drop_nested(roots):
    """Unique roots; a root inside another root is dropped, so nothing is walked twice."""
    out = []
    for r in sorted({norm_root(r) for r in roots}, key=lambda x: (len(x), x.lower())):
        lr = r.lower().rstrip("\\") + "\\"
        if not any(lr.startswith(o.lower().rstrip("\\") + "\\") for o in out):
            out.append(r)
    return out


def parse_since(s):
    try:
        dt = datetime.fromisoformat(s.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        sys.exit(f"new_files_since: --since {s!r} is not an ISO 8601 time (for example 2030-01-01T09:30)")
    if dt.tzinfo is None:
        dt = dt.astimezone()  # local time
    return dt


def local_iso(t):
    return datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")


def birth(st):
    b = getattr(st, "st_birthtime", None)  # Python 3.12 and later
    return st.st_ctime if b is None else b  # st_ctime is the creation time on Windows before 3.12


def type_of(name, types, all_types):
    """(matched, ext): matched is the extension that put the file on the list, or None."""
    low = name.lower()
    ext = os.path.splitext(low)[1]
    if all_types:
        return ext or "(none)", ext
    if ext in types:
        return ext, ext
    if ext in STAGE_SUFFIX:
        inner = os.path.splitext(low[: -len(ext)])[1]
        if inner in types:
            return inner + ext, ext
    return None, ext


def sniff(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    for sig, kind in MAGIC:
        if head.startswith(sig):
            return kind
    return None


class Hider:
    """%USERPROFILE% and %USERNAME% in place of the literal profile path and user name."""

    def __init__(self, keep):
        self.pairs = []
        if not keep:
            prof, user = os.environ.get("USERPROFILE"), os.environ.get("USERNAME")
            if prof:
                self.pairs.append((prof.rstrip("\\").lower(), "%USERPROFILE%"))
            if user:
                self.pairs.append(("\\" + user.lower() + "\\", "\\%USERNAME%\\"))

    def __call__(self, s):
        if not s or not self.pairs:
            return s
        for lit, token in self.pairs:
            low = s.lower()
            i = low.find(lit)
            while i >= 0:
                s = s[:i] + token + s[i + len(lit):]
                low = s.lower()
                i = low.find(lit, i + len(token))
        return s


def walk_root(root, since, args, types, skip_names, hide, found):
    r = {"path": hide(root), "exists": os.path.isdir(root), "dirs": 0, "files": 0, "matched": 0,
         "reparse_skipped": 0, "cache_skipped": 0, "errors": 0, "seconds": 0.0, "skipped_reason": None}
    if not r["exists"]:
        r["skipped_reason"] = "not found"
        return r, [], [], []
    try:
        st0 = os.stat(root, follow_symlinks=False)
        if getattr(st0, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
            tag = getattr(st0, "st_reparse_tag", 0)
            r["skipped_reason"] = f"root is a reparse point ({REPARSE_TAGS.get(tag, hex(tag))}); pass its target with --root"
            return r, [], [], []
    except OSError as e:
        r["skipped_reason"] = f"cannot stat: {e.strerror or e}"
        return r, [], [], []
    t0 = time.monotonic()
    reparse, caches, errors = [], [], []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError as e:
            r["errors"] += 1
            if len(errors) < SAMPLE:
                errors.append({"path": hide(d), "error": e.strerror or str(e)})
            continue
        r["dirs"] += 1
        lnames = None
        parent_low = os.path.basename(os.path.dirname(d)).lower()
        for e in entries:
            try:
                isdir = e.is_dir(follow_symlinks=False)
            except OSError:
                isdir = False
            if isdir or e.is_symlink():
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError as ex:
                    r["errors"] += 1
                    if len(errors) < SAMPLE:
                        errors.append({"path": hide(e.path), "error": ex.strerror or str(ex)})
                    continue
                attrs = getattr(st, "st_file_attributes", 0)
                if attrs & FILE_ATTRIBUTE_REPARSE_POINT or e.is_symlink():
                    if attrs & FILE_ATTRIBUTE_DIRECTORY or isdir:
                        r["reparse_skipped"] += 1
                        if len(reparse) < SAMPLE:
                            tag = getattr(st, "st_reparse_tag", 0)
                            reparse.append({"path": hide(e.path), "tag": REPARSE_TAGS.get(tag, hex(tag))})
                        continue
                    # a file symlink or cloud placeholder: listed from its own metadata, never opened
                elif isdir:
                    low = e.name.lower()
                    skip = low in skip_names
                    if not skip and args.default_skips:
                        if low in ALWAYS_SKIP or (low == "ac" and parent_low == "packages"):
                            skip = True
                        elif low == "cache":
                            if lnames is None:
                                lnames = {x.name.lower() for x in entries}
                            skip = bool(lnames & PROFILE_MARKERS)
                    if skip:
                        r["cache_skipped"] += 1
                        if len(caches) < SAMPLE:
                            caches.append(hide(e.path))
                        continue
                    stack.append(e.path)
                    continue
            r["files"] += 1
            matched, ext = type_of(e.name, types, args.all)
            if matched is None and not args.sniff:
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            b, m = birth(st), st.st_mtime
            if b < since and m < since:
                continue
            if args.min_size and st.st_size < args.min_size:
                continue
            attrs = getattr(st, "st_file_attributes", 0)
            sniffed = None
            if matched is None:
                if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                sniffed = sniff(e.path)
                if not sniffed:
                    continue
                matched = "sniff:" + sniffed
            why = [w for w, t in (("created", b), ("modified", m)) if t >= since]
            found.append({"path": hide(e.path), "root": hide(root), "size": st.st_size, "created": local_iso(b),
                          "modified": local_iso(m), "why": why, "type": matched,
                          "reparse": bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT), "_t": max(b, m)})
            r["matched"] += 1
    r["seconds"] = round(time.monotonic() - t0, 1)
    return r, reparse, caches, errors


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", required=True)
    ap.add_argument("--root", action="append", default=[])
    ap.add_argument("--min-size", type=int, default=0)
    ap.add_argument("--ext")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--sniff", action="store_true")
    ap.add_argument("--skip-dir", action="append", default=[])
    ap.add_argument("--no-default-skips", dest="default_skips", action="store_false")
    ap.add_argument("--out")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--max-lines", type=int, default=30)
    ap.add_argument("--keep-paths", action="store_true")
    args = ap.parse_args()

    since_dt = parse_since(args.since)
    since = since_dt.timestamp()
    types = TYPES
    if args.ext:
        types = {("." + x.strip().lstrip(".")).lower() for x in args.ext.split(",") if x.strip()}
    skip_names = {s.strip().lower() for s in args.skip_dir if s.strip()}
    hide = Hider(args.keep_paths)
    roots = drop_nested(args.root or default_roots())

    t0 = time.monotonic()
    found, root_rows = [], []
    skipped = {"reparse": [], "cache_dirs": [], "errors": []}
    for root in roots:
        row, rp, cd, er = walk_root(root, since, args, types, skip_names, hide, found)
        root_rows.append(row)
        for k, v in (("reparse", rp), ("cache_dirs", cd), ("errors", er)):
            skipped[k].extend(v[: max(0, SAMPLE - len(skipped[k]))])
    found.sort(key=lambda x: x["_t"], reverse=True)
    for f in found:
        del f["_t"]

    result = {
        "schema": "app-debloat.new-files/1", "tool_version": TOOL_VERSION,
        "captured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "params": {"since": since_dt.isoformat(timespec="seconds"), "roots": [hide(r) for r in roots],
                   "types": "all" if args.all else sorted(types), "sniff": args.sniff, "min_size": args.min_size,
                   "default_skips": args.default_skips, "skip_dir": sorted(skip_names)},
        "elapsed_s": round(time.monotonic() - t0, 1),
        "totals": {k: sum(r[k] for r in root_rows) for k in ("dirs", "files", "matched", "reparse_skipped",
                                                             "cache_skipped", "errors")},
        "roots": root_rows,
        "skipped_examples": skipped,
        "files": found,
    }
    text = json.dumps(result, indent=1, ensure_ascii=False)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    if not args.summary:
        if not args.out:
            sys.stdout.write(text + "\n")
        return
    tot = result["totals"]
    print(f"new_files_since: since {result['params']['since']}, {len(roots)} root(s), {tot['dirs']} folders and "
          f"{tot['files']} files walked in {result['elapsed_s']} s, {tot['matched']} match(es)")
    for r in root_rows:
        if r["skipped_reason"]:
            print(f"  root {r['path']}: NOT WALKED ({r['skipped_reason']})")
            continue
        print(f"  root {r['path']}: {r['files']} files, {r['matched']} match(es); skipped {r['reparse_skipped']} "
              f"reparse folder(s), {r['cache_skipped']} cache folder(s); {r['errors']} unreadable folder(s); {r['seconds']} s")
    for f in found[: args.max_lines]:
        print(f"    {f['modified'] if 'modified' in f['why'] and 'created' not in f['why'] else f['created']} "
              f"{'+'.join(f['why']):16} {human(f['size']):>9}  {f['type']:12} {f['path']}")
    if len(found) > args.max_lines:
        print(f"    ... {len(found) - args.max_lines} more in the JSON")
    if args.out:
        print(f"out: {args.out}")


if __name__ == "__main__":
    main()
