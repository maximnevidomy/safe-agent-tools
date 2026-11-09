import { describe, expect, it } from "vitest";
import { scanProject, verdict } from "../src/launch-check";

const r = (path: string, text: string) => scanProject([{ path, text }]).map((f) => f.rule);
const jwt = (role: string) => "eyJhbGciOiJIUzI1NiJ9." + Buffer.from(JSON.stringify({ role })).toString("base64url") + ".c2lnbmF0dXJlMTIz";

describe("launch-check", () => {
  it("flags a table without RLS and accepts one with RLS (even when enabled in another file)", () => {
    expect(r("m.sql", "create table public.notes (id int);")).toContain("rls-missing");
    expect(r("m.sql", "create table public.notes (id int);\nalter table public.notes enable row level security;")).not.toContain("rls-missing");
    const two = scanProject([
      { path: "1.sql", text: 'create table if not exists "notes" (id int);' },
      { path: "2.sql", text: "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;" },
    ]);
    expect(two.map((f) => f.rule)).not.toContain("rls-missing");
  });
  it("ignores commented-out SQL and other schemas", () => {
    expect(r("m.sql", "-- create table public.x (id int);")).toEqual([]);
    expect(r("m.sql", "create table private.x (id int);")).toEqual([]);
  });
  it("flags anon update/delete grants as high, anon insert as info, anon select as nothing", () => {
    expect(r("m.sql", "grant insert, update on public.t to anon;")).toContain("anon-write-grant");
    expect(r("m.sql", "grant insert on public.t to anon;")).toEqual(["public-insert"]);
    expect(r("m.sql", "grant select on public.t to anon;")).toEqual([]);
  });
  it("flags open write policies but not scoped ones", () => {
    expect(r("m.sql", "create policy p on public.t for all to anon using (true) with check (true);")).toContain("policy-open-write");
    expect(r("m.sql", "create policy p on public.t for select using (true);")).toEqual([]);
    expect(r("m.sql", "create policy p on public.t for insert to anon, authenticated with check (true);")).toEqual(["public-insert"]);
    expect(r("m.sql", "create policy p on public.t for insert to authenticated with check (auth.uid() = user_id);")).not.toContain("policy-open-write");
  });
  it("flags SECURITY DEFINER without search_path only", () => {
    const bad = "create function f() returns int language sql security definer as $$ select 1 $$;";
    const good = "create function f() returns int language sql security definer set search_path = public as $$ select 1 $$;";
    expect(r("m.sql", bad)).toContain("definer-search-path");
    expect(r("m.sql", good)).not.toContain("definer-search-path");
    expect(r("m.sql", bad + "\nalter function public.f() set search_path = public;")).not.toContain("definer-search-path");
  });
  it("tells service_role keys from public anon keys", () => {
    expect(r("a.ts", `const k = "${jwt("service_role")}";`)).toContain("service-role-key");
    expect(r("a.ts", `const k = "${jwt("anon")}";`)).not.toContain("service-role-key");
  });
  it("flags committed env files with private values, treats public-only ones as info, ignores examples", () => {
    expect(r(".env", "STRIPE_SECRET=abc")).toContain("env-committed");
    expect(r("app/.env.local", "A=1")).toContain("env-committed");
    expect(r(".env", "VITE_SUPABASE_URL=https://x.supabase.co")).toEqual(["env-public-only"]);
    expect(r(".env.example", "A=")).toEqual([]);
  });
  it("lists functions with verify_jwt=false for manual review", () => {
    expect(r("supabase/config.toml", "[functions.hook]\nverify_jwt = false\n")).toContain("verify-jwt-off");
  });
  it("gives a block verdict on high findings and pass on a clean project", () => {
    expect(verdict(scanProject([{ path: "m.sql", text: "create table public.t (id int);" }]))).toBe("block");
    expect(verdict(scanProject([{ path: "m.sql", text: "create table public.t (id int);\nalter table public.t enable row level security;" }]))).toBe("pass");
  });
});
