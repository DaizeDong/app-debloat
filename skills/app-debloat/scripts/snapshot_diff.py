#!/usr/bin/env python3
"""Diff two inventory.ps1 snapshots: added, removed and changed items per category.

Items are matched by their stable "key". Fields that change on every run (PIDs, window lists,
creation times) are ignored, so a "changed" entry means something an analyst should look at:
a service start mode, a task action, a file hash, an IFEO value, a firewall rule state.

Usage:
  python snapshot_diff.py BEFORE.json AFTER.json --out diff.json [--summary] [--category files ...]

Output never mixes JSON and text:
  --out FILE    write the JSON diff to FILE.
  --summary     print a readable summary (warnings, roots, then the persistence, runtime, update
                and files sections) to stdout. Without --out, --summary prints only the summary.
  neither       print only the JSON diff to stdout.
Nothing goes to stderr except real errors, so PowerShell does not wrap the output as
NativeCommandError.

When either snapshot capped a root (more PE files than -MaxFiles, or the walk hit -MaxEntries),
the files of that root are reported as "capped" instead of added/removed, because which files got
detail depends on the cap. Changed items (same key on both sides) are still reported.
When a root's binary fingerprint changes, the changed, removed and added binaries of that root are
listed under the warning. Exit code 0 always; the diff is evidence, not a verdict.
"""
import argparse
import json
import sys

TOOL_VERSION = "1.1.0"

GROUPS = {
    "persistence": ["installs", "services", "tasks", "run_keys", "other_autostart", "ifeo", "com", "shell_ext", "tsf",
                    "url_protocols", "progids", "file_assoc", "firewall", "toast", "shortcuts", "wmi", "bits", "appx",
                    "autoruns", "placeholders"],
    "runtime": ["processes", "module_hosts", "connections", "dns_cache"],
    "update": ["pending_update"],
    "files": ["files", "config_files"],
}
# Fields that differ between runs without meaning anything.
VOLATILE = {
    "*": {"pid"},
    "processes": {"parent_pid", "created", "threads", "windows", "session", "helper_suspect"},
    "module_hosts": set(),
    "connections": {"state", "local", "remote_names"},
    "files": {"mtime", "attributes"},
    "pending_update": {"mtime"},
    "services": {"state"},
}
SET_FIELDS = {"modules_from_roots", "module_names_only", "sources", "open_with", "actions_on", "flags"}
FILE_CATS = ("files", "config_files", "placeholders")


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        d = json.load(fh)
    if not str(d.get("schema", "")).startswith("app-debloat.inventory/"):
        sys.exit(f"snapshot_diff: {path} is not an inventory snapshot (schema={d.get('schema')!r})")
    return d


def index(items):
    out = {}
    for it in items or []:
        k = it.get("key") or json.dumps(it, sort_keys=True)
        n, base = 1, k
        while k in out:
            n += 1
            k = f"{base}#dup{n}"
        out[k] = it
    return out


def norm(field, v):
    if field in SET_FIELDS and isinstance(v, list):
        return sorted(json.dumps(x, sort_keys=True) if not isinstance(x, str) else x.lower() for x in v)
    return v


def changed_fields(cat, a, b):
    skip = VOLATILE["*"] | VOLATILE.get(cat, set()) | {"key"}
    out = {}
    for f in sorted(set(a) | set(b)):
        if f in skip:
            continue
        va, vb = norm(f, a.get(f)), norm(f, b.get(f))
        if va != vb:
            out[f] = [a.get(f), b.get(f)]
    return out


def brief(cat, it):
    """One short label per item for the text summary."""
    for f in ("path", "name", "image", "aumid", "verb", "handler", "clsid", "entry", "display_name", "ext", "id",
              "uninstall_key"):
        if it.get(f):
            label = str(it[f])
            break
    else:
        label = it.get("key", "?")
    extra = ""
    if cat == "processes" and it.get("command_line"):
        extra = " :: " + it["command_line"][:120]
    elif cat == "connections":
        extra = f" -> {it.get('remote') or it.get('local')}"
    elif cat in ("run_keys", "ifeo") and it.get("value") is not None:
        extra = f" = {str(it.get('value'))[:100]}"
    elif cat == "shell_ext" and isinstance(it.get("effective"), dict):
        extra = f" [effective: {it['effective'].get('state')} via {it['effective'].get('source')}]"
    elif cat == "dns_cache":
        extra = f" = {it.get('data')}"
    elif cat == "pending_update":
        ver = f", {it['display_version']}" if it.get("display_version") else ""
        extra = f" ({it.get('kind')}{ver})"
    return label + extra


def incomplete_roots(snap):
    """Roots whose file lists depend on a cap: {lower path: {"capped": bool, "entries_truncated": bool}}.

    tool_version 1.0.0 snapshots only have stats.truncated, which covers both causes."""
    out = {}
    for r in snap.get("roots", []):
        st = r.get("stats") or {}
        legacy = "entries_truncated" not in st
        capped = bool(r.get("capped") or st.get("capped") or (legacy and st.get("truncated")))
        ent = bool(st.get("entries_truncated") or (legacy and st.get("truncated")))
        if capped or ent:
            out[r["path"].lower()] = {"capped": capped, "entries_truncated": ent}
    for p, fp in (snap.get("fingerprints") or {}).items():
        if fp.get("capped"):
            out.setdefault(p.lower(), {"capped": True, "entries_truncated": False})
    return out


def root_of(it):
    return str(it.get("root") or "").lower()


def binary_row(it):
    return {"rel": it.get("rel") or it.get("path"), "sha256": it.get("sha256"),
            "file_version": it.get("file_version"), "signer": it.get("signer")}


def fingerprint_changes(A, B, capped_roots):
    fa, fb = A.get("fingerprints", {}), B.get("fingerprints", {})
    files_a = index(A.get("items", {}).get("files"))
    files_b = index(B.get("items", {}).get("files"))
    out = []
    for p in sorted(set(fa) & set(fb)):
        if fa[p].get("sha256") == fb[p].get("sha256"):
            continue
        pl = p.lower()
        ia = {k: v for k, v in files_a.items() if root_of(v) == pl}
        ib = {k: v for k, v in files_b.items() if root_of(v) == pl}
        changed = [{"rel": ib[k].get("rel"), "before": binary_row(ia[k]), "after": binary_row(ib[k])}
                   for k in sorted(set(ia) & set(ib)) if ia[k].get("sha256") != ib[k].get("sha256")]
        out.append({"root": p, "before": fa[p], "after": fb[p], "capped": pl in capped_roots,
                    "changed_files": changed,
                    "removed_files": [binary_row(ia[k]) for k in sorted(set(ia) - set(ib))],
                    "added_files": [binary_row(ib[k]) for k in sorted(set(ib) - set(ia))]})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--out", help="JSON output path; without it and without --summary the JSON goes to stdout")
    ap.add_argument("--summary", action="store_true", help="print a readable summary to stdout (never mixed with JSON)")
    ap.add_argument("--category", action="append", help="limit to these categories")
    ap.add_argument("--max-lines", type=int, default=12, help="items listed per category in the text summary")
    args = ap.parse_args()
    A, B = load(args.before), load(args.after)

    warnings = []
    if A.get("host", {}).get("elevated") != B.get("host", {}).get("elevated"):
        warnings.append("Elevation differs between snapshots: some added/removed items may only be visibility changes.")
    if A.get("params", {}).get("app") != B.get("params", {}).get("app"):
        warnings.append("Snapshots were taken with different -App patterns.")
    if A.get("tool_version") != B.get("tool_version"):
        warnings.append(f"inventory.ps1 versions differ ({A.get('tool_version')} vs {B.get('tool_version')}).")

    ra = {r["path"].lower(): r for r in A.get("roots", [])}
    rb = {r["path"].lower(): r for r in B.get("roots", [])}
    inc_a, inc_b = incomplete_roots(A), incomplete_roots(B)
    capped_roots = set(inc_a) | set(inc_b)
    fp_changes = fingerprint_changes(A, B, capped_roots)
    if fp_changes:
        warnings.append("Binary fingerprint changed (update, repair or a self-swap at launch ran): re-run inventory, "
                        "launch-chain and reinstall analysis before trusting the old plan. Changed and removed "
                        "binaries are listed per root.")
    if capped_roots:
        warnings.append("Some roots were capped (MaxFiles/MaxEntries); their files are reported as capped, not "
                        "added/removed: " + ", ".join(sorted(capped_roots)))

    cats = args.category or sorted(set(A.get("items", {})) | set(B.get("items", {})))
    result = {"schema": "app-debloat.snapshot-diff/1", "tool_version": TOOL_VERSION,
              "before": {"file": args.before, "captured_at": A.get("captured_at"), "elevated": A.get("host", {}).get("elevated")},
              "after": {"file": args.after, "captured_at": B.get("captured_at"), "elevated": B.get("host", {}).get("elevated")},
              "warnings": warnings,
              "roots": {"added": sorted(set(rb) - set(ra)), "removed": sorted(set(ra) - set(rb))},
              "fingerprint_changes": fp_changes,
              "capped_roots": {"before": inc_a, "after": inc_b},
              "access_failures": {"before": len(A.get("access_failures", [])), "after": len(B.get("access_failures", []))},
              "categories": {}, "counts": {}}

    def depends_on_cap(cat, it):
        # PE hashing capped: only "files" depends on it. Walk stopped early: all file categories do.
        r = root_of(it)
        states = [x[r] for x in (inc_a, inc_b) if r in x]
        return any(v["entries_truncated"] or (cat == "files" and v["capped"]) for v in states)

    for cat in cats:
        ia, ib = index(A.get("items", {}).get(cat)), index(B.get("items", {}).get(cat))
        added = [ib[k] for k in sorted(set(ib) - set(ia))]
        removed = [ia[k] for k in sorted(set(ia) - set(ib))]
        capped = None
        if cat in FILE_CATS and capped_roots:
            sup_add = [it for it in added if depends_on_cap(cat, it)]
            sup_rem = [it for it in removed if depends_on_cap(cat, it)]
            if sup_add or sup_rem:
                added = [it for it in added if not depends_on_cap(cat, it)]
                removed = [it for it in removed if not depends_on_cap(cat, it)]
                capped = {"roots": sorted({root_of(it) for it in sup_add + sup_rem}),
                          "added_suppressed": len(sup_add), "removed_suppressed": len(sup_rem)}
        changed = []
        for k in sorted(set(ia) & set(ib)):
            ch = changed_fields(cat, ia[k], ib[k])
            if ch:
                changed.append({"key": k, "fields": ch, "item": ib[k]})
        if added or removed or changed or capped:
            result["categories"][cat] = {"added": added, "removed": removed, "changed": changed}
            if capped:
                result["categories"][cat]["capped"] = capped
        result["counts"][cat] = {"before": len(ia), "after": len(ib), "added": len(added), "removed": len(removed),
                                 "changed": len(changed)}
        if capped:
            result["counts"][cat]["capped"] = capped["added_suppressed"] + capped["removed_suppressed"]

    text = json.dumps(result, indent=1, ensure_ascii=False)
    if args.out:
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

    say = print
    say(f"snapshot diff: {A.get('captured_at')} -> {B.get('captured_at')}")
    for w in warnings:
        say(f"  WARNING: {w}")
        if not w.startswith("Binary fingerprint changed"):
            continue
        for fc in fp_changes:
            note = " (capped: the removed and added lists may be incomplete)" if fc["capped"] else ""
            say(f"    root {fc['root']}{note}")
            for tag, lst in (("~", fc["changed_files"]), ("-", fc["removed_files"]), ("+", fc["added_files"])):
                for n, row in enumerate(lst):
                    if n >= args.max_lines:
                        say(f"       ... {len(lst) - n} more in the JSON")
                        break
                    if tag == "~":
                        b, a = row["before"], row["after"]
                        if b.get("file_version") or a.get("file_version"):
                            say(f"       ~ {row['rel']} {b.get('file_version')} -> {a.get('file_version')}")
                        else:
                            say(f"       ~ {row['rel']} sha256 {str(b.get('sha256'))[:12]} -> {str(a.get('sha256'))[:12]}")
                    else:
                        say(f"       {tag} {row['rel']} {row.get('file_version') or ''}".rstrip())
    for k in ("added", "removed"):
        for p in result["roots"][k]:
            say(f"  root {k}: {p}")
    known = {c for m in GROUPS.values() for c in m}
    for group, members in GROUPS.items():
        lines = []
        extra = [c for c in result["categories"] if c not in known] if group == "persistence" else []
        for cat in members + extra:
            d = result["categories"].get(cat)
            if not d:
                continue
            head = f"  [{cat}] +{len(d['added'])} -{len(d['removed'])} ~{len(d['changed'])}"
            cap = d.get("capped")
            if cap:
                head += (f"  capped: {cap['added_suppressed']} added and {cap['removed_suppressed']} removed not "
                         f"compared under {', '.join(cap['roots'])}")
            lines.append(head)
            shown = 0
            for tag, lst in (("+", d["added"]), ("-", d["removed"])):
                for it in lst:
                    if shown >= args.max_lines:
                        break
                    lines.append(f"     {tag} {brief(cat, it)}")
                    shown += 1
            for c in d["changed"]:
                if shown >= args.max_lines:
                    break
                fields = ", ".join(f"{f}: {str(v[0])[:40]} -> {str(v[1])[:40]}" for f, v in list(c["fields"].items())[:3])
                lines.append(f"     ~ {brief(cat, c['item'])} ({fields})")
                shown += 1
            total = len(d["added"]) + len(d["removed"]) + len(d["changed"])
            if total > shown:
                lines.append(f"     ... {total - shown} more in the JSON")
        say(f"{group}: {'no change' if not lines else ''}".rstrip())
        for ln in lines:
            say(ln)


if __name__ == "__main__":
    main()
