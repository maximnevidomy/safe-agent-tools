# safe-agent-tools

Hardened rebuilds of ten popular "agent tool" ideas that are useful but weak on security, plus one showcase
project that chains all ten in a single agent run and proves each works and each attack is stopped.
TypeScript, zero runtime dependencies, 127 tests, `npm audit` clean.

**Proof, not claims:** run `npm run showcase` and read [SHOWCASE_REPORT.md](SHOWCASE_REPORT.md): 10/10 legitimate uses work, 10/10 attacks are stopped, and a 9-step end-to-end pipeline passes.

| Module | Idea it replaces | The risk we removed |
|---|---|---|
| `safe-fetch` | API Anything (call any URL/API from an agent) | SSRF: host allowlist, https only, private/reserved IP block on every resolved record, connection pinned to the checked IP, redirects re-validated, size/time caps, rate limiter |
| `llm-router` | FreeLLMAPI / OmniRoute (multi-provider failover) | Data leakage: per-provider sensitivity ceiling, PII/secret redaction, metadata-only logs, circuit breaker |
| `bybit-readonly` | Bybit trading-mcp | Account takeover: GET-only allowlist, no key/sub-account/transfer/order tools, testnet default, refuses keys with trade/withdraw rights |
| `safe-reach` | Agent-Reach | ToS and account risk: official GitHub API and RSS only, no cookies, output reduced to whitelisted fields |
| `ig-webhook` | InstaMation | Spoofed/replayed events and spam: HMAC signature on raw body, constant-time token check, replay drop, per-sender rate limit, opt-out, human handover, no message text stored |
| `safe-exec` | CLI-Anything (give agents any CLI) | Command injection: allowlist by name, no shell, argument checks, scrubbed environment, timeout and output cap |
| `local-index` | xerj (local code/doc search for agents) | Secret and path leaks: never indexes `.env`/keys/symlinks, confined to root, redacted snippets, no network, no `curl\|sh` install |
| `skill-scanner` | clawscan / vibe-shield | Poisoned skills: flags pipe-to-shell, hidden unicode, prompt injection, exfil endpoints, credential reads before a skill is loaded |
| `approval-gate` | 37studio-style auto-publishing | Unwanted posts: signed, expiring, single-use human approval bound to the exact payload |
| `launch-check` | check-pre-lancamento (Lovable security list) | Missing RLS, anon write grants, open policies, definer functions without search_path, committed secrets |

See [THREAT_MODEL.md](THREAT_MODEL.md) for what each module does and does not protect against.

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
CI runs on every push: tests, typecheck, `npm audit`, CodeQL, and OpenSSF Scorecard. Dependabot keeps
dev dependencies current. The attack tests in `test/` are the executable part of the threat model.
