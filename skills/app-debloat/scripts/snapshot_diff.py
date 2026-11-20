#!/usr/bin/env python3
"""Diff two inventory.ps1 snapshots: added, removed and changed items per category.

Items are matched by their stable "key". Fields that change on every run (PIDs, window lists,
creation times) are ignored, so a "changed" entry means something an analyst should look at:
a service start mode, a task action, a file hash, an IFEO value, a firewall rule state.

Usage:
  python snapshot_diff.py BEFORE.json AFTER.json [--out diff.json] [--category files ...]

Writes the JSON diff to --out (or stdout) and a short text summary to stdout (stderr when the
JSON goes to stdout). Exit code 0 always; the diff is evidence, not a verdict.
"""
import argparse
import json
import sys

TOOL_VERSION = "1.0.0"

GROUPS = {
    "persistence": ["installs", "services", "tasks", "run_keys", "other_autostart", "ifeo", "com", "shell_ext", "tsf",
                    "url_protocols", "progids", "file_assoc", "firewall", "toast", "shortcuts", "wmi", "bits", "appx",
                    "autoruns", "placeholders"],
    "runtime": ["processes", "module_hosts", "connections"],
    "files": ["files", "config_files"],
}
# Fields that differ between runs without meaning anything.
VOLATILE = {
    "*": {"pid"},
    "processes": {"parent_pid", "created", "threads", "windows", "session"},
    "module_hosts": set(),
    "connections": {"state", "local", "remote_names"},
    "files": {"mtime", "attributes"},
    "services": {"state"},
}
SET_FIELDS = {"modules_from_roots", "module_names_only", "sources", "open_with", "actions_on"}


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
    for f in ("path", "name", "image", "aumid", "verb", "handler", "clsid", "entry", "display_name", "ext", "id"):
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
    return label + extra


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--out", help="JSON output path (default: stdout)")
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
    fa, fb = A.get("fingerprints", {}), B.get("fingerprints", {})
    fp_changes = []
    for p in sorted(set(fa) & set(fb)):
        if fa[p].get("sha256") != fb[p].get("sha256"):
            fp_changes.append({"root": p, "before": fa[p], "after": fb[p]})
    if fp_changes:
        warnings.append("Binary fingerprint changed (update or repair ran): re-run inventory, launch-chain and reinstall analysis before trusting the old plan.")

    cats = args.category or sorted(set(A.get("items", {})) | set(B.get("items", {})))
    result = {"schema": "app-debloat.snapshot-diff/1", "tool_version": TOOL_VERSION,
              "before": {"file": args.before, "captured_at": A.get("captured_at"), "elevated": A.get("host", {}).get("elevated")},
              "after": {"file": args.after, "captured_at": B.get("captured_at"), "elevated": B.get("host", {}).get("elevated")},
              "warnings": warnings,
              "roots": {"added": sorted(set(rb) - set(ra)), "removed": sorted(set(ra) - set(rb))},
              "fingerprint_changes": fp_changes,
              "access_failures": {"before": len(A.get("access_failures", [])), "after": len(B.get("access_failures", []))},
              "categories": {}, "counts": {}}
    for cat in cats:
        ia, ib = index(A.get("items", {}).get(cat)), index(B.get("items", {}).get(cat))
        added = [ib[k] for k in sorted(set(ib) - set(ia))]
        removed = [ia[k] for k in sorted(set(ia) - set(ib))]
        changed = []
        for k in sorted(set(ia) & set(ib)):
            ch = changed_fields(cat, ia[k], ib[k])
            if ch:
                changed.append({"key": k, "fields": ch, "item": ib[k]})
        if added or removed or changed:
            result["categories"][cat] = {"added": added, "removed": removed, "changed": changed}
        result["counts"][cat] = {"before": len(ia), "after": len(ib), "added": len(added), "removed": len(removed), "changed": len(changed)}

    text = json.dumps(result, indent=1, ensure_ascii=False)
    summary_stream = sys.stdout
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(text + "\n")
        summary_stream = sys.stderr
    try:
        summary_stream.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    def say(s=""):
        print(s, file=summary_stream)

    say(f"snapshot diff: {A.get('captured_at')} -> {B.get('captured_at')}")
    for w in warnings:
        say(f"  WARNING: {w}")
    for k in ("added", "removed"):
        for p in result["roots"][k]:
            say(f"  root {k}: {p}")
    for group, members in GROUPS.items():
        lines = []
        for cat in members + ([c for c in result["categories"] if group == "persistence" and not any(c in m for m in GROUPS.values())]):
            d = result["categories"].get(cat)
            if not d:
                continue
            lines.append(f"  [{cat}] +{len(d['added'])} -{len(d['removed'])} ~{len(d['changed'])}")
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
        say(f"{group}: {'no change' if not lines else ''}")
        for ln in lines:
            say(ln)


if __name__ == "__main__":
    main()
