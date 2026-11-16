import { test } from "node:test";
import assert from "node:assert/strict";
import {
  authorizeRequest,
  constantTimeEqual,
  getAuthConfig,
  signSession,
  verifySession,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  type AuthRequest,
} from "../src/lib/security/auth-core";

const TOKEN = "t".repeat(24) + "-cyberhuntlab-test-token-0123456789";
const OTHER = "o".repeat(24) + "-cyberhuntlab-other-token-987654321";
const NOW = 1_800_000_000;
const env = { APP_ACCESS_TOKEN: TOKEN };

function req(opts: { method?: string; path?: string; headers?: Record<string, string> } = {}): AuthRequest {
  const headers = new Map(Object.entries({ host: "lab.example", ...(opts.headers || {}) }).map(([k, v]) => [k.toLowerCase(), v]));
  return { method: opts.method || "GET", pathname: opts.path || "/api/chat", header: (name) => headers.get(name.toLowerCase()) ?? null };
}

test("sem APP_ACCESS_TOKEN, rotas protegidas ficam bloqueadas (fail-closed, 503)", async () => {
  const decision = await authorizeRequest(req(), {}, NOW);
  assert.equal(decision.ok, false);
  assert.equal(!decision.ok && decision.status, 503);
});

test("token curto demais é tratado como não configurado", async () => {
  assert.equal(getAuthConfig({ APP_ACCESS_TOKEN: "curto" }).configured, false);
  const decision = await authorizeRequest(req({ headers: { "x-app-token": "curto" } }), { APP_ACCESS_TOKEN: "curto" }, NOW);
  assert.equal(!decision.ok && decision.status, 503);
});

test("rotas públicas não exigem sessão, mesmo sem token configurado", async () => {
  for (const path of ["/api/health", "/api/auth/login", "/api/auth/session", "/api/auth/session/"]) {
    const decision = await authorizeRequest(req({ path, method: "POST" }), {}, NOW);
    assert.deepEqual(decision, { ok: true, via: "public" }, path);
  }
});

test("sem credenciais retorna 401", async () => {
  const decision = await authorizeRequest(req(), env, NOW);
  assert.equal(!decision.ok && decision.status, 401);
});

test("cabeçalho x-app-token correto autoriza; incorreto retorna 401", async () => {
  assert.deepEqual(await authorizeRequest(req({ headers: { "x-app-token": TOKEN } }), env, NOW), { ok: true, via: "header" });
  const bad = await authorizeRequest(req({ headers: { "x-app-token": TOKEN + "x" } }), env, NOW);
  assert.equal(!bad.ok && bad.status, 401);
});

test("x-app-token não sofre bloqueio CSRF em POST (cabeçalho personalizado exige preflight)", async () => {
  const decision = await authorizeRequest(req({ method: "POST", headers: { "x-app-token": TOKEN, origin: "https://evil.example" } }), env, NOW);
  assert.equal(decision.ok, true);
});

test("sessão assinada válida autoriza GET", async () => {
  const cookie = `${SESSION_COOKIE}=${await signSession(TOKEN, NOW)}`;
  assert.deepEqual(await authorizeRequest(req({ headers: { cookie } }), env, NOW + 60), { ok: true, via: "session" });
});

test("sessão expirada, adulterada ou de outro token é recusada", async () => {
  const value = await signSession(TOKEN, NOW);
  assert.equal(await verifySession(TOKEN, value, NOW + SESSION_TTL_SECONDS + 1), false, "expirada");
  const [v, exp, sig] = value.split(".");
  assert.equal(await verifySession(TOKEN, `${v}.${Number(exp) + 3600}.${sig}`, NOW), false, "validade estendida");
  assert.equal(await verifySession(TOKEN, `${v}.${exp}.${sig.slice(0, -2)}AA`, NOW), false, "assinatura alterada");
  assert.equal(await verifySession(OTHER, value, NOW), false, "assinada com outro token");
  assert.equal(await verifySession(TOKEN, "v1.9999999999.abc", NOW), false, "validade além do TTL");
  assert.equal(await verifySession(TOKEN, "", NOW), false);
  assert.equal(await verifySession(TOKEN, "lixo", NOW), false);
});

test("o cookie de sessão nunca contém o token de acesso", async () => {
  const value = await signSession(TOKEN, NOW);
  assert.equal(value.includes(TOKEN), false);
  assert.equal(value.includes(TOKEN.slice(0, 16)), false);
});

test("POST com cookie e Origin de outro site retorna 403 (CSRF)", async () => {
  const cookie = `${SESSION_COOKIE}=${await signSession(TOKEN, NOW)}`;
  const decision = await authorizeRequest(req({ method: "POST", headers: { cookie, origin: "https://evil.example" } }), env, NOW);
  assert.equal(!decision.ok && decision.status, 403);
});

test("POST com cookie sem nenhum indício de origem retorna 403", async () => {
  const cookie = `${SESSION_COOKIE}=${await signSession(TOKEN, NOW)}`;
  const decision = await authorizeRequest(req({ method: "DELETE", headers: { cookie } }), env, NOW);
  assert.equal(!decision.ok && decision.status, 403);
});

test("POST com cookie e mesma origem é aceito (Origin, Sec-Fetch-Site ou Referer)", async () => {
  const cookie = `${SESSION_COOKIE}=${await signSession(TOKEN, NOW)}`;
  const variants: Array<Record<string, string>> = [{ origin: "https://lab.example" }, { "sec-fetch-site": "same-origin" }, { referer: "https://lab.example/app" }];
  for (const extra of variants) {
    const decision = await authorizeRequest(req({ method: "POST", headers: { cookie, ...extra } }), env, NOW);
    assert.equal(decision.ok, true, JSON.stringify(extra));
  }
  const crossSite = await authorizeRequest(req({ method: "POST", headers: { cookie, "sec-fetch-site": "cross-site" } }), env, NOW);
  assert.equal(crossSite.ok, false);
});

test("comparação em tempo constante", () => {
  assert.equal(constantTimeEqual("abc", "abc"), true);
  assert.equal(constantTimeEqual("abc", "abd"), false);
  assert.equal(constantTimeEqual("abc", "abcd"), false);
  assert.equal(constantTimeEqual("", ""), true);
});
