# Known Limitations

As of **Phase 9 (evaluation harness, 2026-10-29)**. This list must be updated every
phase; anything not explicitly implemented must remain listed here or in
`docs/IMPLEMENTATION_STATE.md`.

## Security controls still absent or narrowed (do not claim otherwise)

1. **Execution is in-process and mock-only.** The registry, gateway, execution
   authorization, and four deterministic mock adapters exist and are tested (email
   search/read, file search/read, text summarize, in-memory external sink). There are no
   real connectors, no shell, no arbitrary network access, and no operating-system
   sandbox. The digest-bound authorization is an in-process guardrail against accidental
   bypass; malicious in-process code could still forge calls through private internals.
   Process isolation is Phase 10.
2. **Input defense is advisory, heuristic, and only gates the request path.** Phase 3 adds
   deterministic injection detection, trust labels, and session signals; Phase 8 consumes
   the dispositions in `POST /v1/requests` (`REJECT`/`QUARANTINE` stop before intent,
   `FLAG`/`PASS` continue). It still cannot authorize, and it does not inspect model
   output or tool results. Detection accuracy is modest (regex heuristics over normalized
   text): homoglyphs are detected as indicators but not converted before matching,
   coverage is English-pattern based, quoted/educational content can still raise FLAG
   findings, and novel/paraphrased or non-text attacks can be missed. Phase 9 measured
   detection 14 TP / 3 TN / 3 FP / 0 FN and gating 13 TP / 5 TN / 1 FP / 1 FN on its
   20-case input fixture; the three hard-negative false positives are reported in
   `evaluation/reports/evaluation_report.json`, not tuned away. Phase 6 output DLP is a
   separate deterministic control at the gateway; it is not an input classifier.
3. **Approvals have a decision route, but no delivery/UI/resumption.** Phase 8 exposes
   `POST /v1/approvals/{approval_id}/decision` with a token carried only in the signed
   body, and `POST /v1/requests` creates an approval in-process for gateway-eligible
   `ASK_USER` actions. There is still **no approval UI, token-delivery transport,
   approver directory, notification channel, revocation operation, or background expiry
   sweeper**, and an approved action cannot be resumed through `/v1/requests` in Phase 8
   (no client approval field). Pending/approved requests expire lazily on the next
   decide/consume. The starter policy still enables no approval-eligible tool, so
   approvals are exercised in dedicated test bundles. Self-approval requires an explicit
   policy flag; role rules trust the resolver's role membership.
4. **Intent binding is server-issued but narrow.** The `/v1/requests` route issues and
   consumes a sealed, request/principal/policy-bound manifest in-process and enforces its
   concrete action/resource/destination/parameter/use constraints. The default extractor
   is the two-scenario mock; `MODEL_PROVIDER=local` selects a strict Ollama-compatible
   provider whose semantic accuracy is unmeasured. There is no general planning, no
   client-carried manifest, and no model context beyond the extraction prompt.
5. **Audit lifecycle coverage is limited to the paths that exist.** The gateway emits
   the full request→proposal→inspection→decision→execution→inspection→response sequence;
   the approval service emits `APPROVAL_REQUESTED`/`_DECIDED`/`_CONSUMED`/`_EXPIRED`; the
   intent service emits `INTENT_CREATED`/`_FAILED`; Phase 8 ingress emits
   `REQUEST_RECEIVED`, `PRINCIPAL_RESOLVED`/`_REJECTED`, and `INPUT_INSPECTED`.
   `SECURITY_ALERT_RAISED` still has **no producer** until Phase 10 alerting work. Audit
   rows are queryable by derived columns, but there is no query API/UI. A denial whose
   append fails remains a denial (no side effect exists) and the append is logged;
   pre-execution audit failure on a would-be action denies, and post-execution failure
   withholds the result.
6. **No AI SOC.** No analytics component exists.
7. **Rate limiting is per process and fixed-window.** Phase 8 adds four per-verified-
   principal buckets (requests, tool calls, authenticated invalid requests, approval
   decisions). They are in-memory and not shared across workers, so an N-worker deployment
   effectively multiplies each limit by N. A shared store is future work. Request
   deadlines exist for tool proposals (`REQUEST_TIMEOUT_SECONDS`), but the local-model
   extraction call has its own per-attempt timeout and is not included in that deadline.
8. **Principal resolution requires the trusted host.** `DevPrincipalResolver` returns one
   fixed synthetic principal under `development`/`test` and still runs behind the host
   HMAC middleware; `TestPrincipalResolver` is constructible only under `APP_ENV=test` and
   is not selectable via settings/factory. `HostPrincipalResolver` verifies the
   host-signed assertion against the configured key's `host_id`/`audience`/tenant scope
   and fails closed on every mismatch. There is no end-user login, token refresh, or
   permission system; the host owns user authentication.
9. **The HTTP surface is a trusted-host integration, not a public API.** All three `/v1`
   routes require the HMAC headers and one signed body; there is no browser/CORS model,
   per-user OAuth, API-key tier, or public rate-limit/abuse program. `POST /v1/requests`
   is the only execution surface.
10. **Risk scoring is a small, uncalibrated factor set.** `risk-v2` preserves the
    `risk-v1` side-effect/destination/registration-data-class weights and adds only a
    bounded 2-4/5-8/9+ resource-breadth factor (5/10/15). Since Phase 6 the data class
    used for risk/policy is the *effective* class: the registration's declared class
    raised by deterministic DLP findings (never lowered). There are still no anomaly,
    identity, session, or historical factors, and weights remain experimental. Phase 9
    measures exact score/factor/band conformance and ordering only; it does **not**
    calibrate the weights or thresholds, because no larger labeled calibration set
    exists. Thresholds (40/80) are unchanged. No score or approval can override
    a hard denial. An adapter/registration change that does not change the policy or
    threshold files does not change the combined policy hash; rotate policy
    version/hash when registration facts change. DLP configuration changes rotate the
    DLP config hash, not the policy hash.
11. **Concurrency bounds are per process/per event loop.** `asyncio.Semaphore` limits are
    not shared across workers (no Redis/DB limiter); the in-memory sink is not shared
    between processes either. Multi-worker deployment is a later operational concern.
12. **No policy hot-reload.** The process keeps its startup-loaded bundle; readiness
    detects file drift (503) but does not reload. Atomic reload (blueprint section 10.6)
    is future work.
13. **Destination allowlisting is exact-match only.** No wildcard or pattern matching in
    v1; non-ASCII paths/queries and IPv6 zone IDs are rejected outright. Phase 6's
    destination trust map is also exact-canonical and must cover every registered
    external-mutation destination exactly (missing or dead entries refuse startup).
14. **Capability inventory exceeds the enabled policy.** `mock_files.search` is
    registered (blueprint section 14.1) but absent from the starter policy, so it is
    registered-but-disabled and denied `unknown_tool`. Enabling it requires a policy edit
    and fixture coverage; this is deliberate.

## Environment and tooling

15. **Compose credentials are disposable development values.** The PostgreSQL password
    (`firewall_dev_only`) and the Compose host-auth key are public and dev-only; the
    settings validator refuses the documented sample database password **and** the
    all-zero HMAC sample secret outside `development`/`test`.
16. **Container hardening is minimal.** The image runs as a non-root user (uid 10001,
    verified in Compose) and installs only locked dependencies from digest-pinned base
    images, but no seccomp/AppArmor profile, read-only root filesystem, or image
    vulnerability scanning is in place yet.
17. **Secret scanning is local-only.** Gitleaks 8.30.1 is pinned in `scripts/check.sh`
    (`dir` + `git`, redacted, fails if missing or on findings); there is no CI system, so
    the scan runs when the operator runs the gate. `.gitleaks.toml` allowlists exactly
    the one documented disposable Compose dev key.
18. **No SBOM.** CycloneDX artifact generation is Phase 10.
19. **Minimal schema plus derived audit metadata.** The tables are `host_request_nonces`,
    `audit_events` (baseline `d15b46c49950`; Phase 7 derived metadata migration
    `f7a8b9c0d1e2`), `session_security_state` (Phase 3, `c7f1a2b3d4e5`), and
    `approval_requests` (Phase 5, `e5a1c2b3d4f6`). Audit payloads still live in
    `audit_events.canonical_event_bytes`; the Phase 7 columns (`event_type`,
    `request_id`, `trace_id`, `call_id`, `occurred_at`, `component`) are derived and
    verifier-checked, not authoritative. Expired session rows and pending/approved
    approval rows are transitioned lazily on access; there is no scheduled
    retention/expiry sweeper, so the nonce, session, approval, and audit tables grow until
    an operator prunes them. No purge automation exists.
20. **No CI configuration.** `scripts/check.sh` (8 steps) is the gate.

## Verification gaps in this environment

21. **No coverage measurement.**
22. **No markdown linter installed;** memory-file link checks are scripted ad hoc.
23. **"Fresh clone" has not been repeated since Phase 0a.** The repository is under git
    with a linear history, but the clean-copy approximation was not rerun as a true
    `git clone` in a new directory.

## Behavioral notes

24. Readiness depends on PostgreSQL being reachable; a `503 not_ready` response is
    expected when the database is down and is not an error of the API itself. Readiness
    also reports `policy_self_checks` plus `policy_version`/`policy_hash`,
    re-evaluated on every probe: editing the policy or fixture file at runtime flips
    readiness to 503 (deliberate drift detection).
25. Audit append failure after an already-executed mock side effect yields outcome
    `AUDIT_FAILED` with no result returned; the side effect is not rolled back (the sink is
    in-memory mock state). Real compensating actions are out of scope for v1.
26. Detector verdicts are evidence, not truth: `REJECT` on a heuristic hit can be a false
    positive (quoted content is downgraded, but other contextual uses are not fully
    modeled), and `PASS` never means "safe" — it means "no configured finding matched".
    The `dev-1` disposition config is intentionally conservative and editable.
27. Session signals are counters only and are not yet an authorization or scoring input;
    multi-turn escalation logic (used by risk/session factors) is later-phase work. The
    store is available on `app.state` but no route authenticates a session identifier yet.
28. **Intent manifests cannot cross a process boundary or be carried by a client.** The
    manifest is a sentinel-sealed in-process object, not a signed token. `/v1/requests`
    keeps issuance and verification in the same process; no route accepts a
    client-carried manifest.
29. **The default extractor is the mock implementation.** It recognizes only the two
    documented demo requests and rejects forward/send/delete/upload/share phrasing;
    everything else is clarified. `MODEL_PROVIDER=local` selects
    `LocalModelIntentExtractor` with a strict, bounded provider; semantic accuracy is
    unmeasured, the model is never an authorization input, and no cloud adapter exists.
30. **Intent use limits are per process and in memory.** `IntentUsageTracker` fails
    closed at 10,000 live manifests and purges on expiry, but a multi-worker deployment
    would enforce `max_uses` independently per worker; a shared store is later work.
31. **Manifest request binding relies on a server-assigned `request_id`.** The gateway
    verifies the id but has no request-body digest; the Phase 8 route generates unique
    request ids and never accepts a client-chosen id as a manifest binding.
32. **Constraint syntax is intentionally narrow.** Exact tool/action, resource ids,
    canonical destinations, and scalar parameter values only (no wildcards, prefixes,
    ranges, or float values). This can require clarification for legitimate requests
    that the extractor expresses too coarsely; it never widens execution.
33. **Output DLP is deterministic pattern matching, not a classifier.** The shipped
    `1.0.1` configuration has five patterns (canary shape, private-key header, `sk-` API
    key, credential assignment, email). There is no entropy scan, semantic model,
    multilingual PII support, or detection of secrets without a configured shape.
    `PASS` means "no configured pattern matched", never "the content is safe"; false
    negatives/positives are documented in `docs/OUTPUT_DLP_FALSE_POSITIVES.md`.
34. **Response `REVIEW` is operationally a block.** No review queue, reviewer UI, release
    token, or post-review transport exists; `BLOCK`, `REVIEW`, and failed inspection all
    suppress the complete result (`InvocationOutcome.response_blocked`). A caller cannot
    retrieve a suppressed result.
35. **DLP inspects only validated tool arguments and the complete buffered result.** It
    does not inspect model prompts/streams (no model path exists), content fetched
    inside a future real adapter, or local-write destinations (only external mutations
    require a destination). Read-only actions are inspected but must not present a
    destination; doing so is an inspection failure.
36. **Over-redaction is deliberate and can suppress valid responses.** Credential
    redaction is line-scoped and starts at the first non-space value character, so a
    trailing comment or multi-word passphrase is removed whole; a redaction that violates
    a strict result schema or the result-size bound suppresses the entire response rather
    than releasing an invalid value.
37. **No per-resource classification metadata.** The effective class is the registry
    declaration raised by deterministic inspection of the arguments/result; a real
    connector's per-file/per-record labels are future work. A registration is still the
    floor and cannot be lowered by content.
38. **Destination trust covers only external mutations.** It is an exact-canonical map
    with startup coverage of registered `EXTERNAL_MUTATION` destinations; local-write
    policy and per-tenant destination trust are not modeled in Phase 6.
39. **The audit chain has no external anchor.** A plain local hash chain is
    tamper-evident, not tamper-proof. Mutation, reordering, and middle deletion are
    detected, but deleting the newest event(s) leaves a shorter chain that still verifies;
    an attacker who can rewrite the database consistently can produce a different valid
    chain. Detecting truncation/rewrite requires an externally stored head
    hash + sequence checkpoint (transparency log, signed daily digest, or separate
    store), which Phase 8 does not deploy. The verifier is read-only, loads one chain into
    memory, and is intended for the v1 single-chain deployment; no scheduled verification
    job, audit query API/UI, per-event signature, or automated retention exists. Guidance:
    `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`.
40. **The runtime is a fixed demo plan, not a planner.** `/v1/requests` executes only one
    `mock_email.read` for a single `email-N` followed by `text.summarize`; any manifest
    with a relative time window or another constraint shape returns `NO_ACTION`. It does
    not chain arbitrary tools, retry with a model, or resume after approval. Real
    connectors and planning are later work; the gateway remains the only execution path.
41. **The local model is optional and never authoritative.** It receives the user request
    text (after input inspection) and returns advisory constraints; its output is bounded,
    strictly validated, and unable to set authority, approvals, policy, or risk. A
    provider timeout/failure yields `503 model_unavailable` with no manifest. Prompt
    privacy and model pinning remain operator concerns. Phase 9 measures only
    deterministic transcript conformance, not live-model semantic accuracy, because the
    suite runs offline. No cloud model adapter exists.
42. **Streaming and real-time progress are absent.** Responses are buffered, inspected,
    and released or suppressed whole (ADR-003). No SSE/WebSocket endpoint exists, and the
    approval decision route does not execute the approved action.

## Evaluation-specific limits (Phase 9)

43. **The dataset is small, synthetic, and self-authored.** It has 106 cases
    (42 dev / 34 validation / 30 holdout), written by the same project that implements
    the controls. It supports reproducibility and regression, not an unbiased estimate of
    field performance. The holdout was not used for tuning, but it is not an independent
    third-party sample.
44. **No public benchmark adapter exists.** InjecAgent, AgentDojo, or any other public
    benchmark is not vendored or adapted; no result is comparable to a benchmark run
    without matching the model, tools, scaffold, and configuration. Adding an adapter
    requires a verified license, pinned version, reproducible download hash, and explicit
    opt-in (ADR-016).
45. **Authorization evaluation is in-process and mock-only.** It runs the real gateway,
    registry, policy engine, and DLP over mock adapters, a fixed clock, an in-memory
    audit recorder, and a sink store. It does not exercise PostgreSQL durability, HTTP
    ingress, host authentication, approvals, or real connectors. The 20-case authorization
    matrix is not evidence of real-connector completeness.
46. **Intent evaluation is not live-model accuracy.** Cases use `MockIntentExtractor` and
    deterministic transcript-backed local-provider outputs. An 18/18 status match
    measures adapter/gating conformance on those fixtures, not the semantic quality of an
    arbitrary local model.
47. **Risk evaluation does not calibrate.** The 18 risk fixtures confirm exact scores,
    factors, bands, and ordering for the current uncalibrated `risk-v2` weights. There is
    no labeled calibration set, so no probability/calibration claim is made and the 40/80
    thresholds remain operating points, not validated cutoffs.
48. **Latency is local and in-process.** The reported p50/p95/p99 values are per-case
    wall-clock measurements on the machine named in the report. They exclude HTTP,
    database, network, real adapters, and concurrency, and are not production latency or
    a throughput claim.
49. **The measured detector false positives are deliberate.** Three hard-negative input
    cases (`in-dev-quote-01`, `in-dev-readthis-01`, `in-val-quote-01`) fail their benign
    expectation. They remain in the dataset and in the report; Phase 9 did not tune
    detector patterns or dispositions to improve the metric.
50. **DLP matrices are pattern-scoped.** The five deterministic DLP patterns pass the
    fixtures designed to exercise them; this is not exhaustive secret/PII coverage and does
    not measure semantic, entropy, multilingual, or unseen-secret detection.
51. **Evaluation is not a CI service.** The 15-case quick subset runs inside the pytest
    suite and the 8-step local gate; the full 106-case run is manual/scheduled. No
    coverage measurement exists.
52. **Report metadata names the checked-out source revision.** `metadata.git.commit` is
    read at run time. A report committed afterwards names its parent revision unless
    regenerated; the reproduction command and dataset hashes identify the exact run.
