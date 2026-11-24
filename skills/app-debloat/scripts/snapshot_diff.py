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

Planned changes (after an apply):
  --journal FILE         the engine's journal.jsonl. Each active entry (not undone) explains only its
                         own effect, so a vendor change to the same object still shows:
                           service    a start-mode change to Disabled (Running to Stopped is not compared)
                           task       a state change to Disabled
                           firewall   the rule added
                           ifeo       the Debugger value added (a new key holding only it, or a new value)
                           file2dir, dir2file  the removal of the file or folder (with everything under
                                      it) and a placeholders item of the primitive's kind (directory
                                      for file2dir, file for dir2file) appearing at that path. That
                                      placeholder disappearing, or a real file back at its path, stays
                                      unexplained
                           acl        an sddl change on that path (with emptyFirst, removals under it)
                           watchtask  the tool's own <Prefix>Debloat-Watch task added (labelled self)
                         A service, task, firewall rule or IFEO entry that was removed or added, or that
                         changed in any other field, stays unexplained.
  --expect-removed FILE  one planned path per line (# comments, %VAR% tokens and * ? globs allowed);
                         the removal of the path and everything under it, and a placeholders item of
                         either kind appearing at that path, count as planned; a placeholder that
                         disappears from that path does not.
  Expected items move to "expected" in each category (each with planned_by) and are not counted as
  added/removed/changed. The fingerprint warning fires only when a root has a binary change that no
  plan explains; a planned removal explains a removed binary, never a changed or added one.

Noise that is not reported:
  - Windows paths (keys, path, parent_path, command_line and other path-like values) are compared
    without regard to letter case.
  - A field that exists only in the newer snapshot schema (absent from every item of that category
    on the side taken with another inventory.ps1 version) is listed under schema_only_fields, not as
    a change.
  - Processes whose command line names this skill's scripts folder or an agent shell snapshot are
    the agent's own and are dropped (self_excluded counts them); inventory.ps1 1.2.0 and later
    already leaves them out.
"""
import argparse
import fnmatch
import json
import os
import re
import sys

TOOL_VERSION = "1.3.0"

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
# Fields holding Windows paths or command lines: compared without regard to case.
PATH_FIELDS = {"path", "parent_path", "command_line", "root", "rel", "image", "target", "execute", "workdir",
               "arguments", "install_location", "filter_full_path", "stub_path", "ime_file", "layout_file",
               "program", "main_exe", "command", "value", "location", "uninstall_key", "container"}
PATHLIKE = re.compile(r"^(?:[A-Za-z]:[\\/]|%[A-Za-z_][\w()]*%[\\/]|\\\\)")
SELF_CMD = re.compile(r"[\\/]skills[\\/]+app-debloat[\\/]+scripts[\\/]|[\\/]shell-snapshots[\\/]", re.I)


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        d = json.load(fh)
    if not str(d.get("schema", "")).startswith("app-debloat.inventory/"):
        sys.exit(f"snapshot_diff: {path} is not an inventory snapshot (schema={d.get('schema')!r})")
    return d


def index(items):
    out = {}
    for it in items or []:
        k = (it.get("key") or json.dumps(it, sort_keys=True)).lower()
        n, base = 1, k
        while k in out:
            n += 1
            k = f"{base}#dup{n}"
        out[k] = it
    return out


def fold(v, pathish=False):
    """Lower-case Windows paths (by field name or by shape), recursively."""
    if isinstance(v, str):
        return v.lower() if pathish or PATHLIKE.match(v) else v
    if isinstance(v, list):
        return [fold(x, pathish) for x in v]
    if isinstance(v, dict):
        return {k: fold(x, pathish or k in PATH_FIELDS) for k, x in v.items()}
    return v


def norm(field, v):
    if field in SET_FIELDS and isinstance(v, list):
        return sorted(json.dumps(fold(x), sort_keys=True) if not isinstance(x, str) else x.lower() for x in v)
    return fold(v, field in PATH_FIELDS)


def schema_only(items_a, items_b, versions_differ):
    """Fields present on one side only, across every item of the category: a schema change, not a data change."""
    if not versions_differ or not items_a or not items_b:
        return set(), set()
    fa = set().union(*(set(x) for x in items_a))
    fb = set().union(*(set(x) for x in items_b))
    return fb - fa, fa - fb


def changed_fields(cat, a, b, ignore=frozenset()):
    skip = VOLATILE["*"] | VOLATILE.get(cat, set()) | {"key"} | set(ignore)
    out = {}
    for f in sorted(set(a) | set(b)):
        if f in skip:
            continue
        va, vb = norm(f, a.get(f)), norm(f, b.get(f))
        if va != vb:
            out[f] = [a.get(f), b.get(f)]
    return out


def canon(p):
    """Comparable Windows path: %VAR% expanded, backslashes, lower case, no trailing separator."""
    if not p:
        return ""
    s = os.path.expandvars(str(p).strip().strip('"')).replace("/", "\\")
    return s.rstrip("\\").lower()


class Plan:
    """What an apply changed on purpose, from --journal and --expect-removed: each primitive's own effect only."""

    def __init__(self):
        self.removed, self.removed_globs = set(), []   # removal of the path and everything under it
        # A placeholder appearing at exactly that path: path -> its kinds ("directory", "file", or "any" when
        # the kind is not known), and a list of (glob, kind).
        self.placeholders, self.placeholder_globs = {}, []
        self.acl = set()   # sddl change at exactly that path
        self.tasks, self.self_tasks, self.services, self.firewall = set(), set(), set(), set()
        self.ifeo = {}   # image name -> Debugger value the engine wrote
        self.sources = []

    def add_path(self, p, placeholder=True, kind="any"):
        c = canon(p)
        if not c:
            return
        glob = "*" in c or "?" in c
        (self.removed_globs.append(c) if glob else self.removed.add(c))
        if placeholder:
            if glob:
                self.placeholder_globs.append((c, kind))
            else:
                self.placeholders.setdefault(c, set()).add(kind)

    def covers_path(self, p):
        """True when the plan removed this path or a folder above it."""
        c = canon(p)
        if not c:
            return False
        if any(c == e or c.startswith(e + "\\") for e in self.removed):
            return True
        return any(fnmatch.fnmatchcase(c, g) or fnmatch.fnmatchcase(c, g + "\\*") for g in self.removed_globs)

    def is_placeholder(self, p, kind):
        """True when the plan puts a placeholder of this kind at exactly this path."""
        c = canon(p)
        if not c:
            return False
        kinds = set(self.placeholders.get(c, ()))
        kinds.update(k for g, k in self.placeholder_globs if fnmatch.fnmatchcase(c, g))
        return "any" in kinds or kind in kinds

    def explain(self, cat, it, how, fields=None):
        """The plan step that explains this added, removed or changed item, or None."""
        fields = fields or {}
        if cat in FILE_CATS or cat == "pending_update":
            p = it.get("path")
            # Only a placeholders item of the primitive's kind is the plan's own placeholder. One that disappears
            # from its path, or a real file or config back at that path, is the vendor undoing the plan.
            own = cat == "placeholders" and self.is_placeholder(p, it.get("kind"))
            if how == "removed" and self.covers_path(p) and not own:
                return "planned removal"
            if how == "added" and own:
                return "planned placeholder"
            if how == "changed" and canon(p) in self.acl and set(fields) <= {"sddl"}:
                return "acl"
            return None
        if cat == "tasks":
            k = str(it.get("key") or "").lower()
            if how == "added" and k in self.self_tasks:
                return "self"
            if how == "changed" and k in self.tasks and set(fields) == {"state"} \
                    and str(fields["state"][1]).lower() == "disabled":
                return "task disabled"
            return None
        if cat == "services":
            name = str(it.get("name") or "").lower()
            if how == "changed" and name in self.services and set(fields) <= {"start_mode", "state"} \
                    and "start_mode" in fields and str(fields["start_mode"][1]).lower() == "disabled" \
                    and ("state" not in fields or [str(x).lower() for x in fields["state"]] == ["running", "stopped"]):
                return "service disabled"
            return None
        if cat == "firewall":
            if how == "added" and (str(it.get("name") or "").lower() in self.firewall
                                   or str(it.get("id") or "").lower() in self.firewall):
                return "firewall rule added"
            return None
        if cat == "ifeo":
            img = str(it.get("image") or "").lower()
            if img not in self.ifeo or it.get("kind", "ifeo") != "ifeo":
                return None
            want = self.ifeo[img]

            def debugger_only(before, after):
                b = {str(k).lower(): v for k, v in (before or {}).items()}
                a = {str(k).lower(): v for k, v in (after or {}).items()}
                if "debugger" in b or "debugger" not in a:
                    return False
                if want is not None and str(a["debugger"]).lower() != str(want).lower():
                    return False
                return {k: v for k, v in a.items() if k != "debugger"} == b

            if how == "added" and not it.get("filters") and debugger_only({}, it.get("values")):
                return "ifeo debugger added"
            if how == "changed" and set(fields) == {"values"} and debugger_only(*fields["values"]):
                return "ifeo debugger added"
            return None
        return None

    def __bool__(self):
        return bool(self.removed or self.removed_globs or self.placeholders or self.acl or self.tasks
                    or self.self_tasks or self.services or self.firewall or self.ifeo)


def load_journal(path, plan):
    """Active journal entries (one per key, 'undone' closes a key), as the engine reads them."""
    active = {}
    with open(path, encoding="utf-8-sig") as fh:
        for n, ln in enumerate(fh, 1):
            ln = ln.strip()
            if not ln:
                continue
            try:
                e = json.loads(ln)
            except ValueError:
                sys.exit(f"snapshot_diff: {path} line {n} is not JSON")
            k = str(e.get("key"))
            kind = e.get("kind", "change")
            if kind == "note":
                continue
            if kind == "undone":
                active.pop(k, None)
            elif k in active:
                # the engine keeps the first original and the latest after-state and data
                active[k]["after"], active[k]["data"] = e.get("after"), e.get("data")
            else:
                active[k] = dict(e)
    counts = {}
    for k, e in active.items():
        prim, d, af = e.get("prim"), e.get("data") or {}, e.get("after") or {}
        if prim in ("file2dir", "dir2file"):
            plan.add_path(d.get("path") or (k[3:] if k.startswith("fs:") else None),
                          kind="directory" if prim == "file2dir" else "file")
        elif prim == "acl":
            if d.get("path"):
                plan.acl.add(canon(d["path"]))
                if d.get("emptyFirst"):
                    plan.add_path(d["path"] + "\\*", placeholder=False)
        elif prim == "task":
            plan.tasks.add(f"task|{d.get('path') or ''}{d.get('name') or ''}".lower())
        elif prim == "watchtask":
            name = d.get("name") or (k[len("watchtask:"):] if k.startswith("watchtask:") else "")
            if name:
                plan.self_tasks.add(("task|\\" + name).lower())
        elif prim == "service":
            plan.services.add(str(d.get("name") or k[4:]).lower())
        elif prim == "firewall":
            plan.firewall.add(str(d.get("name") or k[3:]).lower())
        elif prim == "ifeo":
            plan.ifeo[str(d.get("name") or k[5:]).lower()] = af.get("debugger") if isinstance(af, dict) else None
        else:
            continue
        counts[prim] = counts.get(prim, 0) + 1
    plan.sources.append({"journal": path, "entries": len(active), "used": counts})


def load_expect(path, plan):
    n = 0
    with open(path, encoding="utf-8-sig") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                plan.add_path(ln)
                n += 1
    plan.sources.append({"expect_removed": path, "paths": n})


def brief(cat, it):
    """One short label per item for the text summary."""
    if cat == "tasks" and it.get("name"):
        label = f"{it.get('path') or ''}{it['name']}"
        return label + (" (self)" if it.get("planned_by") == "self" else "")
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
    return {"rel": it.get("rel") or it.get("path"), "path": it.get("path"), "sha256": it.get("sha256"),
            "file_version": it.get("file_version"), "signer": it.get("signer")}


def fingerprint_changes(A, B, capped_roots, plan):
    fa = {p.lower(): (p, v) for p, v in (A.get("fingerprints") or {}).items()}
    fb = {p.lower(): (p, v) for p, v in (B.get("fingerprints") or {}).items()}
    files_a = index(A.get("items", {}).get("files"))
    files_b = index(B.get("items", {}).get("files"))
    out = []
    for pl in sorted(set(fa) & set(fb)):
        (p, va), (_, vb) = fa[pl], fb[pl]
        if va.get("sha256") == vb.get("sha256"):
            continue
        ia = {k: v for k, v in files_a.items() if root_of(v) == pl}
        ib = {k: v for k, v in files_b.items() if root_of(v) == pl}
        changed = [{"rel": ib[k].get("rel"), "path": ib[k].get("path"), "before": binary_row(ia[k]),
                    "after": binary_row(ib[k])}
                   for k in sorted(set(ia) & set(ib)) if ia[k].get("sha256") != ib[k].get("sha256")]
        removed = [binary_row(ia[k]) for k in sorted(set(ia) - set(ib))]
        added = [binary_row(ib[k]) for k in sorted(set(ib) - set(ia))]
        fc = {"root": p, "before": va, "after": vb, "capped": pl in capped_roots,
              "changed_files": changed, "removed_files": removed, "added_files": added, "explained": False}
        if plan:
            # A placeholder replaces a binary: it explains the binary's removal, never a changed or added one.
            planned = {"changed": [], "removed": [r for r in removed if plan.covers_path(r.get("path"))], "added": []}
            fc["planned"] = {t: len(v) for t, v in planned.items()}
            fc["planned_files"] = planned
            fc["removed_files"] = [r for r in removed if not plan.covers_path(r.get("path"))]
            # Explained only when every binary difference is planned and the lists are complete (not capped).
            fc["explained"] = (not fc["capped"] and any(planned.values())
                               and not (fc["changed_files"] or fc["removed_files"] or fc["added_files"]))
        out.append(fc)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--out", help="JSON output path; without it and without --summary the JSON goes to stdout")
    ap.add_argument("--summary", action="store_true", help="print a readable summary to stdout (never mixed with JSON)")
    ap.add_argument("--category", action="append", help="limit to these categories")
    ap.add_argument("--max-lines", type=int, default=12, help="items listed per category in the text summary")
    ap.add_argument("--journal", action="append", default=[], help="engine journal.jsonl: its changes are expected")
    ap.add_argument("--expect-removed", action="append", default=[],
                    help="text file, one planned path or glob per line: removals and placeholders there are expected")
    args = ap.parse_args()
    A, B = load(args.before), load(args.after)
    plan = Plan()
    for j in args.journal:
        load_journal(j, plan)
    for e in args.expect_removed:
        load_expect(e, plan)

    warnings, notes = [], []
    versions_differ = A.get("tool_version") != B.get("tool_version")
    if A.get("host", {}).get("elevated") != B.get("host", {}).get("elevated"):
        warnings.append("Elevation differs between snapshots: some added/removed items may only be visibility changes.")
    if A.get("params", {}).get("app") != B.get("params", {}).get("app"):
        warnings.append("Snapshots were taken with different -App patterns.")
    if versions_differ:
        warnings.append(f"inventory.ps1 versions differ ({A.get('tool_version')} vs {B.get('tool_version')}); "
                        "fields only one version writes are listed under schema_only_fields, not as changes.")

    ra = {r["path"].lower(): r for r in A.get("roots", [])}
    rb = {r["path"].lower(): r for r in B.get("roots", [])}
    inc_a, inc_b = incomplete_roots(A), incomplete_roots(B)
    capped_roots = set(inc_a) | set(inc_b)
    fp_changes = fingerprint_changes(A, B, capped_roots, plan)
    unexplained = [fc for fc in fp_changes if not fc["explained"]]
    if unexplained:
        warnings.append("Binary fingerprint changed (update, repair or a self-swap at launch ran): re-run inventory, "
                        "launch-chain and reinstall analysis before trusting the old plan. Changed and removed "
                        "binaries that no plan explains are listed per root.")
    for fc in fp_changes:
        if fc["explained"]:
            notes.append(f"Binary fingerprint of {fc['root']} changed only by planned changes "
                         f"({sum(fc['planned'].values())} file(s)): expected.")
    if capped_roots:
        warnings.append("Some roots were capped (MaxFiles/MaxEntries); their files are reported as capped, not "
                        "added/removed: " + ", ".join(sorted(capped_roots)))

    cats = args.category or sorted(set(A.get("items", {})) | set(B.get("items", {})))
    result = {"schema": "app-debloat.snapshot-diff/1", "tool_version": TOOL_VERSION,
              "before": {"file": args.before, "captured_at": A.get("captured_at"),
                         "elevated": A.get("host", {}).get("elevated"), "tool_version": A.get("tool_version")},
              "after": {"file": args.after, "captured_at": B.get("captured_at"),
                        "elevated": B.get("host", {}).get("elevated"), "tool_version": B.get("tool_version")},
              "warnings": warnings, "notes": notes, "plan": plan.sources,
              "roots": {"added": sorted(set(rb) - set(ra)), "removed": sorted(set(ra) - set(rb))},
              "fingerprint_changes": fp_changes,
              "capped_roots": {"before": inc_a, "after": inc_b},
              "access_failures": {"before": len(A.get("access_failures", [])), "after": len(B.get("access_failures", []))},
              "schema_only_fields": {}, "self_excluded": {"before": 0, "after": 0},
              "categories": {}, "counts": {}}

    def depends_on_cap(cat, it):
        # PE hashing capped: only "files" depends on it. Walk stopped early: all file categories do.
        r = root_of(it)
        states = [x[r] for x in (inc_a, inc_b) if r in x]
        return any(v["entries_truncated"] or (cat == "files" and v["capped"]) for v in states)

    def not_self(x):
        return not SELF_CMD.search(str(x.get("command_line") or ""))

    for cat in cats:
        la, lb = list(A.get("items", {}).get(cat) or []), list(B.get("items", {}).get(cat) or [])
        if cat == "processes":
            # The agent's own shells and helpers: their command lines name the app, but they are not the app.
            ka, kb = [x for x in la if not_self(x)], [x for x in lb if not_self(x)]
            result["self_excluded"] = {"before": len(la) - len(ka), "after": len(lb) - len(kb)}
            la, lb = ka, kb
        ia, ib = index(la), index(lb)
        new_b, new_a = schema_only(la, lb, versions_differ)
        if new_b or new_a:
            result["schema_only_fields"][cat] = {"after_only": sorted(new_b), "before_only": sorted(new_a)}
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
            ch = changed_fields(cat, ia[k], ib[k], new_b | new_a)
            if ch:
                changed.append({"key": k, "fields": ch, "item": ib[k]})
        expected = None
        if plan:
            exp = {"added": [], "removed": [], "changed": []}
            keep = {"added": [], "removed": [], "changed": []}
            for how, lst in (("added", added), ("removed", removed), ("changed", changed)):
                for x in lst:
                    it = x["item"] if how == "changed" else x
                    why = plan.explain(cat, it, how, x["fields"] if how == "changed" else None)
                    if why:
                        exp[how].append(dict(x, planned_by=why))
                    else:
                        keep[how].append(x)
            if any(exp.values()):
                expected = exp
                added, removed, changed = keep["added"], keep["removed"], keep["changed"]
        if added or removed or changed or capped or expected:
            result["categories"][cat] = {"added": added, "removed": removed, "changed": changed}
            if capped:
                result["categories"][cat]["capped"] = capped
            if expected:
                result["categories"][cat]["expected"] = expected
        result["counts"][cat] = {"before": len(ia), "after": len(ib), "added": len(added), "removed": len(removed),
                                 "changed": len(changed)}
        if capped:
            result["counts"][cat]["capped"] = capped["added_suppressed"] + capped["removed_suppressed"]
        if expected:
            result["counts"][cat]["expected"] = sum(len(v) for v in expected.values())

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
    for src in plan.sources:
        if "journal" in src:
            used = ", ".join(f"{k} {v}" for k, v in sorted(src["used"].items())) or "none usable"
            say(f"  plan: journal {src['journal']} ({src['entries']} active entries; {used})")
        else:
            say(f"  plan: expected removals {src['expect_removed']} ({src['paths']} paths)")
    for w in warnings:
        say(f"  WARNING: {w}")
        if not w.startswith("Binary fingerprint changed"):
            continue
        for fc in unexplained:
            note = " (capped: the removed and added lists may be incomplete)" if fc["capped"] else ""
            if fc.get("planned") and any(fc["planned"].values()):
                note += f" ({sum(fc['planned'].values())} planned change(s) not listed)"
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
    for n in notes:
        say(f"  note: {n}")
    for cat, f in result["schema_only_fields"].items():
        parts = ([f"new {', '.join(f['after_only'])}"] if f["after_only"] else []) + \
                ([f"dropped {', '.join(f['before_only'])}"] if f["before_only"] else [])
        say(f"  schema: [{cat}] {'; '.join(parts)} (not compared)")
    se = result["self_excluded"]
    if se["before"] or se["after"]:
        say(f"  self: dropped the agent's own processes (before {se['before']}, after {se['after']})")
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
            exp = d.get("expected")
            if exp:
                head += f"  planned: +{len(exp['added'])} -{len(exp['removed'])} ~{len(exp['changed'])}"
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
            if exp:
                rows = [("+", it) for it in exp["added"]] + [("-", it) for it in exp["removed"]] + \
                       [("~", dict(c["item"], planned_by=c["planned_by"])) for c in exp["changed"]]
                for tag, it in rows[:args.max_lines]:
                    label = brief(cat, it)
                    why = "" if label.endswith("(self)") else f" ({it['planned_by']})"
                    lines.append(f"     planned {tag} {label}{why}")
                if len(rows) > args.max_lines:
                    lines.append(f"     ... {len(rows) - args.max_lines} more planned in the JSON")
        say(f"{group}: {'no change' if not lines else ''}".rstrip())
        for ln in lines:
            say(ln)


if __name__ == "__main__":
    main()
