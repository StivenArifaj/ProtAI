# Known Limitations

As of **Phase 7 (audit persistence and verification, 2026-10-26)**. This list must
be updated every phase; anything not explicitly implemented must remain listed here or in
`docs/IMPLEMENTATION_STATE.md`.

## Security controls still absent or narrowed (do not claim otherwise)

1. **Execution is in-process and mock-only.** The registry, gateway, execution
   authorization, and four deterministic mock adapters exist and are tested (email
   search/read, file search/read, text summarize, in-memory external sink). There are no
   real connectors, no shell, no arbitrary network access, and no operating-system
   sandbox. The digest-bound authorization is an in-process guardrail against accidental
   bypass; malicious in-process code could still forge calls through private internals.
   Process isolation is Phase 10.
2. **Input defense is advisory, heuristic, and not consumed.** Phase 3 adds deterministic
   injection detection, trust labels, and session signals, but nothing in a request path
   uses them yet: there are no `/v1` routes or model calls, so detection cannot block,
   quarantine, or re-rank anything. Detection accuracy is modest (regex heuristics over
   normalized text): homoglyphs are detected as indicators but not converted before
   matching, coverage is English-pattern based, quoted/educational content can still
   raise FLAG findings, and novel/paraphrased or non-text attacks can be missed. Phase 6
   output DLP is a separate deterministic control at the gateway; it is not an input
   classifier, and input content still has no classification consumer.
3. **Approvals are storage-and-gateway only.** Phase 5 adds a durable
   `approval_requests` table, `ApprovalService`, verified-principal rule evaluation, and
   one-time gateway consumption, but there is **no `/v1/approvals` route, approval UI,
   token-delivery transport, approver directory, notification channel, revocation
   operation, or background expiry sweeper**. Pending/approved requests expire lazily on
   the next decide/consume. The gateway does not create requests automatically; Phase 8's
   host workflow must call `ApprovalService.request` with host-verified facts. The
   starter policy still enables no approval-eligible tool, so approvals are exercised in
   dedicated test bundles. Self-approval requires an explicit policy flag; role rules
   trust the resolver's role membership.
4. **Intent binding is in-process only and uses a mock extractor.** The app-built
   gateway requires a sealed, request/principal/policy-bound manifest and enforces its
   concrete action/resource/destination/parameter/use constraints (Phase 4), but no
   `/v1` route issues or transports a manifest, and the app uses the two-scenario mock
   extractor rather than general natural-language understanding. Trust labels and
   detector findings still have no consumer.
5. **Audit lifecycle coverage is limited to the paths that exist.** The gateway emits
   the full request→proposal→inspection→decision→execution→inspection→response sequence;
   the approval service emits `APPROVAL_REQUESTED`/`_DECIDED`/`_CONSUMED`/`_EXPIRED`; the
   intent service can emit `INTENT_CREATED`/`_FAILED`. `PRINCIPAL_RESOLVED`/`_REJECTED`,
   `INPUT_INSPECTED`, and `SECURITY_ALERT_RAISED` have **no producer** until the Phase 8
   ingress and Phase 10 alerting work; their names exist but no code fakes them. Audit
   rows are queryable by derived columns, but there is no query API/UI. A denial whose
   append fails remains a denial (no side effect exists) and the append is logged;
   pre-execution audit failure on a would-be action denies, and post-execution failure
   withholds the result.
6. **No AI SOC.** No analytics component exists.
7. **No rate limiting or request deadlines.** `/v1/*` routes do not exist; the gateway
   enforces per-call deadlines and per-tool concurrency, but Phase 8 adds request-level
   limits. A request-size bound (64 KiB default) exists since Phase 0b.
8. **Principal resolution is dev-only, test-only, or fail-closed.** `DevPrincipalResolver`
   returns one fixed synthetic principal under `development`/`test`;
   `TestPrincipalResolver` is constructible only under `APP_ENV=test` and is not reachable
   via settings/factory; `HostPrincipalResolver` raises (fails closed) until a later phase
   provides key→principal metadata.
9. **`/v1/*` has no routes yet.** Authenticated requests answer `404` after passing
   authentication (verified in the Phase 0b Docker proof); the gateway is used
   in-process/in tests only until Phase 8.
10. **Risk scoring is a small, uncalibrated factor set.** `risk-v2` preserves the
    `risk-v1` side-effect/destination/registration-data-class weights and adds only a
    bounded 2-4/5-8/9+ resource-breadth factor (5/10/15). Since Phase 6 the data class
    used for risk/policy is the *effective* class: the registration's declared class
    raised by deterministic DLP findings (never lowered). There are still no anomaly,
    identity, session, or historical factors, and weights remain experimental; Phase 9
    calibrates them. Thresholds (40/80) are unchanged. No score or approval can override
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
28. **Intent manifests cannot cross a process boundary or the future API.** The manifest
    is a sentinel-sealed in-process object, not a signed token. A `/v1` route must keep
    issuance and verification in-process or add a server-signed serialization before
    accepting a client-carried manifest; no route accepts one today.
29. **The app's extractor is the mock implementation.** It recognizes only the two
    documented demo requests and rejects forward/send/delete/upload/share phrasing;
    everything else is clarified. `LocalModelIntentExtractor` exists with a strict,
    bounded parser and an injected client interface, but no real provider is wired and
    the model's semantic accuracy is unmeasured (Phase 8/9).
30. **Intent use limits are per process and in memory.** `IntentUsageTracker` fails
    closed at 10,000 live manifests and purges on expiry, but a multi-worker deployment
    would enforce `max_uses` independently per worker; a shared store is later work.
31. **Manifest request binding relies on a server-assigned `request_id`.** The gateway
    verifies the id but has no request-body digest; the Phase 8 route must generate
    unique request ids and must never accept a client-chosen id as a manifest binding.
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
    store), which Phase 7 does not deploy. The verifier is read-only, loads one chain into
    memory, and is intended for the v1 single-chain deployment; no scheduled verification
    job, audit query API/UI, per-event signature, or automated retention exists. Guidance:
    `docs/AUDIT_RETENTION_AND_DATA_HANDLING.md`.
40. **No live `/v1` DLP surface.** As with every phase so far, Phase 6 enforcement is
    in-process and exercised by tests; no route accepts a request or returns a model
    response. The gateway remains the only execution path.
