# Phase <NN><letter> — <Name> — <STATUS>

- **Status:** <NOT STARTED | IN PROGRESS | COMPLETE (VERIFIED) | BLOCKED>
- **Blueprint:** <sections + phase gate reference>
- **Started / completed:** <ISO dates>

## Objective

<One short paragraph: what this phase makes real and why it matters (link blueprint).>

## Deliverables

- [ ] <Deliverable 1 (blueprint reference)>
- [ ] <Deliverable 2 ...>

| Deliverable | Delivered as (files) | Status |
|---|---|---|
| <...> | <...> | <VERIFIED / PARTIAL / NOT IMPLEMENTED> |

## Explicit non-goals

- <What this phase must NOT implement (belongs to a later phase).>

## Decisions and deviations

| Decision / deviation | Rationale | Recorded in |
|---|---|---|
| <...> | <...> | <ADR / docs / IMPLEMENTATION_STATE> |

## Verification evidence

| ID | Command / check | Result |
|---|---|---|
| <V..> | <exact command> | <actual result — never claimed without running> |

(Add new evidence rows to [../TESTING_AND_VERIFICATION.md](../TESTING_AND_VERIFICATION.md) and reference them here.)

## Definition of Done checklist (blueprint <section>)

| DoD item | Status |
|---|---|
| <...> | <PASS / FAIL / N/A + evidence> |

## Known limitations added/closed by this phase

- Added: <items> (update [../KNOWN_ISSUES_AND_LIMITATIONS.md](../KNOWN_ISSUES_AND_LIMITATIONS.md) + [../../docs/KNOWN_LIMITATIONS.md](../../docs/KNOWN_LIMITATIONS.md)).
- Closed: <items + evidence>.

## Handoff

Next task: <phase + plan file>. Preconditions: <gate / environment>. Update
[../IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md), [../NEXT_SESSION.md](../NEXT_SESSION.md), [../CHANGELOG.md](../CHANGELOG.md), and the
[../../docs/](../../docs/) state files in the same task.
