# Public Design Rationale, app-debloat

> TOOL documentation for reusable behavior. The complete research brief, real inputs, scope decisions and evaluation artifacts live in the private companion. Examples here are synthetic.

## Best References (Match or Beat)
- [ChrisTitusTech/winutil](https://github.com/ChrisTitusTech/winutil): declarative tweaks with recorded original values and undo scripts. Borrowed: every manifest action records its original state. Gap: Windows components only, no per-app self-repair handling.
- [undergroundwires/privacy.sexy](https://github.com/undergroundwires/privacy.sexy): reversible primitives (soft delete, placeholder files, service and task disable, IFEO). Borrowed as ideas only (AGPL). Gap: OS components only.
- [SanJerry007/sogou-ime-debloat](https://github.com/SanJerry007/sogou-ime-debloat): the only end-to-end per-app case (inventory, launch chain, encrypted gate, re-install paths, placeholders, IFEO, preboot edit, auto re-apply). The engine generalizes its code.

## Frontier Ideas to Incorporate
- [morluto/rea](https://github.com/morluto/rea) as the default static backend (Ghidra headless, JSON CLI), with ReVa or pyghidra-mcp and a pefile/capstone fallback.
- Evidence-anchored ledgers so analysis survives context resets and hallucinated offsets are caught (inspired by verifiable LLM reverse-engineering workflows).
- Early runtime confirmation with frida and Procmon instead of long static reading.

## Anti-Patterns to Avoid
- Deleting or ACL-locking broadly without a core-function contract; restoring registry only.
- Re-running destructive actions on every logon.
- Trusting file state instead of behavior; trusting UI toggles.
- Publishing extracted keys, decrypted configs or patched binaries.
- Sending keystrokes to a window the agent did not create.

## Proof Bar (How We Show It Is Tested-Real)
- G1: paired read-only analysis tasks on real apps, with and without the skill, scored by an independent evaluator against a frozen rubric (coverage against an evaluator-built oracle, claim correctness, plan and script quality, safety gate).
- G2: held-out trigger queries frozen by the evaluator before implementation, including near-miss negatives (uninstall, Windows-wide debloat, malware, browser ads, cracking).

## Scope and Focus (One Job, Three Modules)
- One job: debloat one installed third-party Windows app durably and reversibly.
- Modules: analysis (inventory, triage, diff, tracer), engine (manifest, build, apply, install, uninstall, journal), verification (snapshot diff and core-function probes driven by the pipeline).
