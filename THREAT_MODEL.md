# Threat model

Attacker model: text the agent reads (web pages, DMs, feeds) may contain instructions or hostile URLs, and
any key or token we hold may leak. Each module limits the blast radius of that.

## safe-fetch
- Protects: SSRF to localhost, private ranges, cloud metadata (169.254.169.254), DNS rebinding, open-redirect hops, credentials in URLs, oversized or slow responses.
- Does not protect: a malicious allowed host returning hostile content (treat output as untrusted data), or abuse of an allowed host's own API.
- Known limit: https only, GET only, no proxy support. Real TLS/DNS behaviour is exercised only through the default transport; tests use injected fakes.

## llm-router
- Protects: sending data to a provider not approved for its sensitivity; secrets/PII in prompts (best-effort regex redaction); content in logs.
- Does not protect: redaction is pattern based and will miss free-text secrets. Anything truly secret must be tagged `secret` and only a local provider may receive it. Providers' own retention policies are outside our control.

## bybit-readonly
- Protects: placing orders, moving funds, changing keys or sub-accounts through this tool; use of over-privileged keys; accidental mainnet use.
- Does not protect: the exchange account itself. Use a key created read-only with an IP allowlist. The key-permission check relies on Bybit's `/v5/user/query-api` response shape and should be verified once against a real testnet key.

## safe-reach
- Protects: ToS-violating cookie scraping, path injection in repo names, hostile markup/links in feeds.
- Does not protect: content accuracy. YouTube transcripts are not included yet (needs a legal channel).

## ig-webhook
- Protects: forged webhooks, replayed events, per-sender spam loops, messaging people who opted out, talking over a human.
- Does not protect: Meta platform policy compliance (24h messaging window, templates) and storage of the ids it keeps. This module is the verification and decision core; the HTTP server, token storage and Meta app review are the integrator's job.

## safe-exec
- Protects: shell injection, running binaries the agent names, secrets inherited from the parent environment, runaway or endless commands.
- Does not protect: what an allowlisted binary itself can do with its arguments. Add `checkArgs` per command (for example forbid `--exec`), and avoid allowlisting interpreters.

## local-index
- Protects: indexing or returning secrets, reading outside the root via `..`, absolute paths or symlinks, leaking PII in snippets (best-effort redaction).
- Does not protect: secrets pasted inside ordinary text files. Keep the root small and review it.

## skill-scanner
- Protects: obvious supply-chain and prompt-injection patterns in skills before loading.
- Does not protect: a determined attacker (static rules can be evaded by obfuscation). Treat `pass` as "no known bad pattern", not as "safe".

## approval-gate
- Protects: actions without human approval, changed payloads, replays, forged and expired approvals.
- Does not protect: a human approving blindly, or a compromised approval secret. In-memory store: single process only, use a database for production.

## launch-check
- Protects: common Supabase/Lovable launch mistakes found statically in migrations, config and source.
- Does not protect: runtime configuration. It reads the migration history, not the live database, so run it alongside a live advisor check.
