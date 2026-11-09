# safe-agent-tools

**Live demo (try every tool in your browser): https://safe-agent-tools.onrender.com**

Hardened rebuilds of ten popular "agent tool" ideas that are useful but weak on security, plus one showcase
project that chains all ten in a single agent run and proves each works and each attack is stopped.
TypeScript, zero runtime dependencies, 146 tests, `npm audit` clean.

![demo](docs/demo.png)

## Run the app
```
npm ci
npm run demo
```
Open http://127.0.0.1:4173. Two tabs:
- **Use it (live):** vet a real GitHub repo (license, activity, README scan), read real Bybit prices with no key, fetch URLs with SSRF protection, scan your real project folders (launch check, skill scan, local search), and run the approval-gate flow for posts.
- **Self-check:** 20 tests (one legitimate use and one attack per module) plus a 9-step agent pipeline.

Folders the app may scan are limited to `DEMO_ROOTS` (default: the parent of this repo).
Windows PowerShell: `$env:DEMO_ROOTS="C:\Users\you\projects"; npm run demo`. macOS/Linux: `DEMO_ROOTS=~/projects npm run demo`.

Optional environment variables: `GITHUB_TOKEN` (higher API limits), `IG_APP_SECRET` and `IG_VERIFY_TOKEN` (enable the Instagram webhook at `/webhook/instagram`), `GATE_SECRET` (stable approval secret), `PORT`.

The app protects itself: 127.0.0.1 only, Host-header check against DNS rebinding, a per-run token on every API call, folder access confined to `DEMO_ROOTS` (symlink safe), capped request bodies, results rendered as text only.

![live app](docs/demo.png)

**Proof, not claims:** run `npm run showcase` and read [SHOWCASE_REPORT.md](SHOWCASE_REPORT.md): 10/10 legitimate uses work, 10/10 attacks are stopped, and a 9-step end-to-end pipeline passes.

| Module | Idea it replaces | The risk we removed |
|---|---|---|
| `safe-fetch` | API Anything (call any URL/API from an agent) | SSRF: host allowlist, https only, private/reserved IP block on every resolved record, connection pinned to the checked IP, redirects re-validated, size/time caps, rate limiter |
| `llm-router` | FreeLLMAPI / OmniRoute (multi-provider failover) | Data leakage: per-provider sensitivity ceiling, PII/secret redaction, metadata-only logs, circuit breaker |
| `bybit-readonly` | Bybit trading-mcp | Account takeover: GET-only allowlist, no key/sub-account/transfer/order tools, testnet default, refuses keys with trade/withdraw rights |
| `safe-reach` | Agent-Reach | ToS and account risk: official GitHub API and RSS only, no cookies, output reduced to whitelisted fields; `auditRepo` gives a real safety score from health signals, the README and a static scan of install scripts, workflows and source (not a proof of safety) |
| `ig-webhook` | InstaMation | Spoofed/replayed events and spam: HMAC signature on raw body, constant-time token check, replay drop, per-sender rate limit, opt-out, human handover, no message text stored |
| `safe-exec` | CLI-Anything (give agents any CLI) | Command injection: allowlist by name, no shell, argument checks, scrubbed environment, timeout and output cap |
| `local-index` | xerj (local code/doc search for agents) | Secret and path leaks: never indexes `.env`/keys/symlinks, confined to root, redacted snippets, no network, no `curl\|sh` install |
| `skill-scanner` | clawscan / vibe-shield | Poisoned skills: flags pipe-to-shell, hidden unicode, prompt injection, exfil endpoints, credential reads before a skill is loaded |
| `approval-gate` | 37studio-style auto-publishing | Unwanted posts: signed, expiring, single-use human approval bound to the exact payload |
| `launch-check` | check-pre-lancamento (Lovable security list) | Missing RLS, anon write grants, open policies, definer functions without search_path, committed secrets |

See [THREAT_MODEL.md](THREAT_MODEL.md) for what each module does and does not protect against.

## Dashboard (per-tool before/after)

`npm run site` writes `site/index.html`: one static page, no scripts, that shows for each of the ten tools the original project, its problem, a security score before and after, the attack table, and a live example produced at build time.

**How the score is measured.** The same attack attempts (`showcase/attacks.ts`, 50 in total) run against a naive baseline we wrote for the idea and against our hardened module. Score = percentage of attacks stopped. The baseline is not the original project's code; facts about originals come from the tool-library review and repo metadata. 100% means "stopped everything in this suite", not "unbreakable". Tests assert the scores, so a regression fails CI.

**Public HTTPS address.** `npm run demo` serves the dashboard at `http://127.0.0.1:4173/dashboard`. Point any HTTPS tunnel at port 4173 and start with `PUBLIC_HOST=<tunnel hostname>`: that hostname serves only the read-only dashboard (and the signature-checked Instagram webhook). The workbench, folder scanning and token endpoints stay reachable only through 127.0.0.1/localhost.

## Real-world run
`launch-check` was run on the Christina Fitness codebase (796 files): verdict **pass**, 0 high, 0 medium, 29 informational notes
(9 public-insert forms, 15 functions with `verify_jwt=false`, 3 public-only env files, 2 HTML sinks). The first run raised 11 high and
4 medium findings; triage showed they were false positives (public Vite keys, insert-only public forms, functions already fixed by a later
`ALTER FUNCTION`), so the scanner was improved and the tests extended. `npm run scan -- <dir>` repeats it on any project.

## Develop
```
npm ci
npm test
npm run typecheck
npm run showcase
```

## Safety score (measured, not claimed)
CI runs on every push: tests, typecheck, `npm audit`, and CodeQL. Dependabot keeps
dev dependencies current. The attack tests in `test/` are the executable part of the threat model.

## Verification status
- Verified by automated tests (146): all ten modules, the app's endpoints, the webhook endpoint (signature, replay, opt-out), and the real HTTPS transport (TLS name check, pinned IP, size cap, timeout) against a local TLS server.
- Verified in a real browser: the live tab on a real project folder, the approval flow, the self-check tab.
- Not verified from the build environment (no outbound internet there): live calls to the GitHub and Bybit APIs. Run the two cards once on your machine to confirm.
- Not built: real sending of Instagram replies (needs a Meta Page token and app review; replies are logged to `data/outbox.jsonl`), a live LLM provider for `llm-router`.

## Public live site (Render)

`render.yaml` is a Render Blueprint for one free web service that runs `showcase/public-server.ts`: the dashboard plus a live "try it" form per tool. The process holds no secrets, has no folder access, stores no input, and rate-limits every visitor (and the whole site). Network tools run in public mode: any public https site on port 443, private networks always blocked.

Deploy: Render dashboard, New, Blueprint, pick this repo. Optional env var `GITHUB_TOKEN` (a token with no scopes) raises GitHub's rate limit for the repo-vetting tool.
The free plan sleeps after 15 minutes without traffic, so a monitor must call `/healthz` at least every 10 minutes to keep it awake.
