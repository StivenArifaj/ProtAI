# Demo Company — Northstar Forge AI (synthetic, realistic)

**Important:** Northstar Forge AI is a **fictional company**. The data generated for it
is synthetic but realistic: every audit event, decision, and alert is produced by the
real ProtAI gateway and written to the real audit chain. It is demo data, not a real
customer's data, and it is not used for training or benchmarking.

Run `uv run --frozen python scripts/seed_company.py` to generate a fresh batch of
activity. The script signs real `/v1` requests with the local dev host key.

## Company profile

**Northstar Forge AI** — an AI-first software development company (Singapore / EU),
~180 employees. It builds custom systems for clients and uses AI heavily in its own
delivery pipeline.

### Departments and principals

| Team | Subject prefix | Typical role |
|---|---|---|
| Engineering | `eng-` | developer |
| Platform / DevOps | `plat-` | operator |
| Security | `sec-` | analyst |
| Data / ML | `ml-` | developer |
| Product | `prod-` | viewer |
| Support | `sup-` | viewer |

### AI tools and systems in daily use

| Tool / action | Purpose | Egress |
|---|---|---|
| `llm.code.generate` | Generate code in the IDE/plugin | internal model gateway |
| `llm.review.pr` | AI code review on pull requests | internal model gateway |
| `github.pr.merge` | Merge a reviewed PR | internal |
| `jira.ticket.update` | Update delivery tickets | internal |
| `confluence.doc.read` | Read internal runbooks | internal |
| `slack.message.send` | Team notifications | internal |
| `email.external.send` | Client communication | **external** |
| `s3.artifact.upload` | Publish build artifacts | **external** |
| `db.customer.query` | Query client data (restricted) | internal |
| `ci.pipeline.trigger` | Trigger deployment pipelines | internal |
| `code.deploy.production` | Production release | **external, sensitive** |

Only the four registered mock tools can actually execute today. Every other tool is
either preview-evaluated (blocked as unknown or DLP-restricted) or reported as a
clarification — which is exactly the security posture a real company would start with:
**unregistered tools cannot bypass the gateway**.

### Representative situations generated

- Developers ask for code generation / PR review → the demo runtime handles supported
  read+summarize intents; other intents clarify (no invented execution).
- A platform engineer proposes artifact uploads and production deploys → blocked by
  egress DLP / unknown tool, with a correlated decision event.
- A support agent tries to email a client with a canary in the message → blocked.
- Prompt-injection attempts in pasted content → rejected by input defense.
- Repeated blocked calls and external-destination attempts → deterministic alerts.

### What to look at in the console after seeding

1. **Logs** — service filters (`gateway`, `api`, `intent`, `soc`, `runtime`), severity,
   search by `BLOCK`, `deploy`, `email`, etc.
2. **Audit Explorer** — click a `POLICY_EVALUATED` BLOCK row and inspect the Decision
   Trace and reason (`dlp_egress_blocked`, `unknown_tool`).
3. **Alerts** — real firings from the deterministic rules over the company's traffic.
4. **Overview** — real counts: audit events, alerts, verified chain head.
