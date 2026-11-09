// Original vs ours, capability by capability. "original" facts come from each project's own README (read 2026-11-09);
// "ours" facts are what the code here does and what the live site was checked against. Status is our honest call.
import type { ToolId } from "./attacks";

export type Cmp = "better" | "same" | "partial" | "missing" | "by-design";
export interface CompareRow { what: string; original: string; ours: string; status: Cmp }

export const COMPARE: Record<ToolId, CompareRow[]> = {
  "safe-fetch": [
    { what: "Reach any site", original: "Replays the site's own hidden requests learned in a browser", ours: "Reads any public page; extracts price, sale price, image", status: "partial" },
    { what: "Sites with no public API", original: "Catalog of 114 pre-learned sites", ours: "Standard product data only (JSON-LD, OpenGraph, microdata)", status: "partial" },
    { what: "Login and cookies", original: "Imports cookies from your browser", ours: "Never uses cookies or sessions", status: "by-design" },
    { what: "Cache, request budget, change tracking", original: "Yes", ours: "Yes: 30 s cache, per-site budget, price change since last check", status: "same" },
    { what: "Errors an agent can act on", original: "Error class plus suggested next step", ours: "Same: class plus what to do next", status: "same" },
    { what: "Attack protection (private networks, redirects, DNS tricks)", original: "Not described", ours: "Every address checked, pinned connection, redirects re-checked", status: "better" },
  ],
  "llm-router": [
    { what: "Failover between providers", original: "Yes", ours: "Yes, with a circuit breaker", status: "same" },
    { what: "Rate-limit handling", original: "Counters per key, learned ceilings", ours: "429 rests the provider; requests-per-minute budget", status: "same" },
    { what: "Smart routing", original: "Six strategies from live scores", ours: "Fast and reliable from observed results", status: "partial" },
    { what: "Sticky conversations and cache", original: "Yes", ours: "Yes; cache never stores secret data", status: "same" },
    { what: "Built-in free providers, OpenAI-style server, dashboard", original: "About 34 providers, full server and UI", ours: "You plug in providers yourself", status: "missing" },
    { what: "Private data protection", original: "Not described", ours: "Each provider has a data level; emails, cards, keys removed before sending", status: "better" },
  ],
  "bybit-readonly": [
    { what: "Market data", original: "23 tools", ours: "13 market tools", status: "partial" },
    { what: "Account reads", original: "Part of 60 account tools", ours: "7 read-only account tools (positions, balance, orders, fees, PnL...)", status: "partial" },
    { what: "Trading, bots, loans, earn, withdrawals", original: "About 300 tools", ours: "None exist in the code, on purpose", status: "by-design" },
    { what: "Protection against a leaked or over-powered key", original: "Approval form in the client; read-only advice in the docs", ours: "Only GET exists; a key with trade or withdraw rights is refused", status: "better" },
    { what: "Testnet", original: "Optional switch", ours: "Default; real exchange needs a double opt-in", status: "better" },
  ],
  "safe-reach": [
    { what: "GitHub", original: "Public data", ours: "Official API, plus a safety score for any repo", status: "better" },
    { what: "Any web page as text", original: "Jina Reader", ours: "Own reader: public https only, size capped, safe links only", status: "same" },
    { what: "YouTube, Reddit, news feeds", original: "yt-dlp, login for Reddit", ours: "Public feeds: channel videos, Reddit, Hacker News, releases", status: "partial" },
    { what: "Video transcripts", original: "Yes (needs a speech-to-text key)", ours: "Not built", status: "missing" },
    { what: "X, Instagram, Facebook, LinkedIn search, XiaoHongShu, Boss", original: "Through your logged-in browser", ours: "Left out: they need your cookies and risk your account", status: "by-design" },
  ],
  "ig-webhook": [
    { what: "Comment-to-DM with a keyword", original: "Yes", ours: "Yes, per post, one DM per person", status: "same" },
    { what: "Public reply and follow-first gate", original: "Yes", ours: "Yes", status: "same" },
    { what: "Click tracking", original: "Per-campaign stats and CTR", ours: "Signed tracked links, no open redirect; no dashboard", status: "partial" },
    { what: "AI replies, several accounts, agency workspaces", original: "Yes", ours: "Not built", status: "missing" },
    { what: "Fake or replayed deliveries, opt-out, human takeover", original: "Not described", ours: "Signature checked, replays dropped, stop honoured, silent while a human answers", status: "better" },
  ],
  "safe-exec": [
    { what: "Make any software usable by an agent", original: "Generates a CLI for GIMP, Blender, LibreOffice and more", ours: "You list the programs you trust, one by one", status: "missing" },
    { what: "Structured JSON output", original: "Yes (--json)", ours: "Always one JSON shape with error class and next step", status: "same" },
    { what: "Agent can discover what exists", original: "SKILL.md and a hub", ours: "describePolicy() lists names and usage", status: "partial" },
    { what: "Shell tricks and secrets", original: "Runs real backends", ours: "No shell, scrubbed environment, timeout and output cap", status: "better" },
  ],
  "local-index": [
    { what: "Keyword search", original: "BM25", ours: "BM25", status: "same" },
    { what: "Code awareness", original: "Tree-sitter symbols, go-to-definition", ours: "Splits camelCase and snake_case, reports lines, regex definitions", status: "partial" },
    { what: "Meaning-based search, many file types, MCP server", original: "Vector search, PDF/DOCX/XLSX, 21 MCP tools", ours: "Not built", status: "missing" },
    { what: "Secrets and escapes", original: "Not described", ours: ".env, keys, symlinks and paths outside the folder are never read", status: "better" },
  ],
  "skill-scanner": [
    { what: "Static rules", original: "clawscan-static", ours: "20 rules incl. pipe-to-shell, secrets, typosquats, hidden characters", status: "same" },
    { what: "Score and recommendation", original: "Per-scanner scores and a gate", ours: "0-100 score and install / review / do not install", status: "same" },
    { what: "AI review, VirusTotal, other scanners", original: "Yes, run side by side", ours: "Not built (would send files out)", status: "missing" },
    { what: "Speed and cost", original: "Docker, API keys, LLM calls", ours: "Instant, local, free", status: "better" },
  ],
  "approval-gate": [
    { what: "One-click approval before publishing", original: "Yes", ours: "Signed token tied to the exact text, single use, expiring", status: "better" },
    { what: "Scheduling and missed posts", original: "Marks posts over 12 h late as missed", ours: "Same rule: never sent late", status: "same" },
    { what: "Publish to 9 platforms, video editor, Autopilot", original: "Yes", ours: "Not built: this is the safety gate in front of them", status: "missing" },
  ],
  "launch-check": [
    { what: "Security checks", original: "20", ours: "Live site: headers, cookies, CORS, leaks, keys in scripts, source maps. Code: open tables, policies, keys", status: "partial" },
    { what: "Launch readiness", original: "10 (SEO, legal, email, backups...)", ours: "SEO, mobile, legal page, robots, sitemap, favicon", status: "partial" },
    { what: "Dependency and git-history scan, email DNS", original: "Yes", ours: "Not built", status: "missing" },
    { what: "Works on a live link anyone can try", original: "Needs an agent and local files", ours: "Paste a link and get two scores", status: "better" },
  ],
};
