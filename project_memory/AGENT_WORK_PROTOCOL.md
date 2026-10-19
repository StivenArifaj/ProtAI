# Agent Work Protocol

Mandatory operating rules for any coding agent working on this repository. Derived from
blueprint §22 (coding-agent operating protocol) and the phase-gate rules in §21.

## Autonomous execution (operator mandate)

The agent is the primary implementation agent and works autonomously across sessions and
context compactions. **The default is to proceed.** Do not stop to ask the operator to
approve routine work, confirm blueprint-determined details, choose between ordinary
engineering approaches, or tell the agent to continue when the roadmap already defines
what comes next. Do not stop after producing a plan when implementation is expected; do
not substitute scaffolding, TODOs, placeholders, mocks, or documentation of future
functionality for a working implementation required by the current phase.

Decision procedure when something is unclear:

- **A —** The specification answers it: follow the specification; do not ask.
- **B —** Several ordinary engineering solutions are valid: choose the safest, most
  maintainable one consistent with the architecture; record consequential choices.
- **C —** A small reversible detail is unspecified: decide, and record it if it
  materially affects future work.
- **D —** Apparent contradiction: investigate blueprint, ADRs, tests, and surrounding
  requirements; resolve only when the governing requirement is clear; record the
  resolution and fix inconsistent documentation.
- **E —** Genuine blocker: ask one concise question (what conflicts/is missing, why the
  agent cannot decide safely, viable options, recommendation) and continue with
  independent work meanwhile.

Phase gates: stop only where the blueprint explicitly requires operator review or
external authorization. A completed phase, by itself, is not a gate: update state files,
memory, and commit, then proceed to the next eligible phase in dependency order. If a
later phase has an unfinished prerequisite, finish the prerequisite first.

Ask the operator only when proceeding would require inventing a product requirement,
making an irreversible or externally consequential decision without authorization,
accessing unavailable credentials or accounts, accepting a material unresolved security
risk, or violating a specified approval gate.

Verification is the agent's responsibility: run the applicable tests, exercise failure
paths, check the diff, fix failures, and report actual commands and results. Never claim
a check passed unless it was actually run. Distinguish implemented-and-verified /
implemented-not-fully-verified / partial / planned / blocked.

## Start-of-task checklist (blueprint §22.1)

Before editing code, the agent MUST:

1. Read this memory ([README.md](README.md) → [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) → [NEXT_SESSION.md](NEXT_SESSION.md)), the
   blueprint section(s) governing the task, [../docs/SECURITY_INVARIANTS.md](../docs/SECURITY_INVARIANTS.md), and the
   relevant module docs/tests.
2. Inspect the current repository state, existing files, diff, and dependency lock —
   never assume the last report matches reality.
3. State the specific files it expects to change and the acceptance criteria.
4. Identify any ambiguity that materially changes security behavior. Ask rather than
   guess; if the blueprint already specifies behavior, follow it.
5. Avoid unrelated refactors and preserve currently passing behavior unless the task
   explicitly changes it.

## The 15 working rules

1. **Read memory and status first.** [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) is the source of truth;
   [NEXT_SESSION.md](NEXT_SESSION.md) says what to do next. Do not rely on chat history.
2. **Read the blueprint section before writing code for it.** Memory files summarize;
   the blueprint specifies. On any conflict, the blueprint wins — record the conflict.
3. **Inspect before editing.** Verify the on-disk state (git status when the repo is
   under git; file inventory otherwise) before trusting any summary.
4. **One small deliverable per task:** schema + tests, policy rule + tests, one route +
   tests, one adapter + tests (§22.2).
5. **Fail closed.** Never swallow exceptions or treat missing data as clean/allowed
   (§22.2).
6. **No policy in prompts or model output**, and the agent never calls tool adapters
   directly — everything goes through the firewall gateway (§22.2, §12.1).
7. **No new dependency without a recorded justification:** why needed, license, runtime
   impact (§22.2).
8. **No hard-coded model IDs, rate limits, keys, absolute local paths, or
   developer-specific configuration** (§22.2).
9. **Never use real secrets or private documents in fixtures**; documented sample dev
   values only (§22.2).
10. **Never weaken a test to make it pass.** Every discovered bug gets a minimal
    regression test (§22.2).
11. **Run the focused tests for the changed module, then `bash scripts/check.sh`** — or
    report precisely why the required environment is unavailable (§22.3).
12. **Inspect the diff for unrequested edits, secrets, raw payload logs, broad exception
    handling, and bypass paths** (§22.3; once the repo is under git, use `git diff`).
13. **Never claim tests pass unless the commands were actually executed and returned
    success.** Report actual commands and results (§22.3).
14. **Report files changed, implementation summary, actual commands/results, remaining
    risks, and any skipped tests.** Update documentation/config examples if contracts
    changed (§22.3).
15. **Keep the memory current.** At the end of every session update
    [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md), [NEXT_SESSION.md](NEXT_SESSION.md), [CHANGELOG.md](CHANGELOG.md), the phase record, and
    [TESTING_AND_VERIFICATION.md](TESTING_AND_VERIFICATION.md) with confirmed facts only; update the `docs/` state
    files (blueprint §22.4) in the same task. **No secrets in memory files.**

Additional standing rules:

- **Defer ≠ delete:** if a planned feature is deferred, update its status and state the
  trigger for implementing it later (§22.2).
- **Security contracts are frozen unless superseded:** changes to HMAC auth, persistence,
  audit-chain, streaming, approvals, or SOC behavior require a new/superseding ADR.
- **All `/v1/*` routes must enforce HMAC before principal resolution**, including when
  `PRINCIPAL_RESOLVER=dev` (§9.3, §18.2). No auth-bypass mode may ever be added.
- **Evidence discipline:** label claims VERIFIED only with a recorded command/result;
  otherwise use REPORTED — NOT REVERIFIED / UNKNOWN.

## End-of-task checklist (blueprint §22.3)

1. Focused tests for the changed module run and pass.
2. `bash scripts/check.sh` exit 0 (or precise environment explanation).
3. Diff inspected (unrequested edits, secrets, raw logs, broad excepts, bypass paths).
4. Report: files changed, summary, actual commands/results, remaining risks, skipped tests.
5. Docs/config updated if contracts changed.
6. Never claim success that was not actually executed.
7. Memory files updated (rule 15).
