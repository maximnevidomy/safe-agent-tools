# safe-agent-tools

Hardened rebuilds of five popular "agent tool" ideas, each of which is useful but unsafe as published.
Private repo. TypeScript, zero runtime dependencies, 65 tests.

| Module | Idea it replaces | The risk we removed |
|---|---|---|
| `safe-fetch` | API Anything (call any URL/API from an agent) | SSRF: host allowlist, https only, private/reserved IP block on every resolved record, connection pinned to the checked IP, redirects re-validated, size/time caps, rate limiter |
| `llm-router` | FreeLLMAPI / OmniRoute (multi-provider failover) | Data leakage: per-provider sensitivity ceiling, PII/secret redaction, metadata-only logs, circuit breaker |
| `bybit-readonly` | Bybit trading-mcp | Account takeover: GET-only allowlist, no key/sub-account/transfer/order tools, testnet default, refuses keys with trade/withdraw rights |
| `safe-reach` | Agent-Reach | ToS and account risk: official GitHub API and RSS only, no cookies, output reduced to whitelisted fields |
| `ig-webhook` | InstaMation | Spoofed/replayed events and spam: HMAC signature on raw body, constant-time token check, replay drop, per-sender rate limit, opt-out, human handover, no message text stored |

See [THREAT_MODEL.md](THREAT_MODEL.md) for what each module does and does not protect against.

## Develop
```
npm ci
npm test
npm run typecheck
```

## Safety score (measured, not claimed)
CI runs on every push: tests, typecheck, `npm audit`, CodeQL, and OpenSSF Scorecard. Dependabot keeps
dev dependencies current. The attack tests in `test/` are the executable part of the threat model.
