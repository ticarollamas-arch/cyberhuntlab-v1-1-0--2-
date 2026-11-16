/**
 * Testes de integração: executam os handlers REAIS das rotas e o middleware com requisições HTTP.
 * Só next/server e @opencode-ai/sdk são substituídos (tests/stubs). Nenhuma chamada de rede é feita.
 */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { calls as opencodeCalls } from "@opencode-ai/sdk";
import { buildZip, forgeDeclaredSizes, renameEntry } from "./helpers/zip-fixtures";

const TOKEN = "integration-token-" + "x".repeat(40);
const BASE = "https://lab.example";
const ORIGIN = { origin: BASE, host: "lab.example" };

type Handler = (req: NextRequest, ctx?: any) => Promise<Response>;
let routes: Record<string, Record<string, Handler>>;
let middleware: (req: NextRequest) => Promise<Response>;

before(async () => {
  process.env.APP_ACCESS_TOKEN = TOKEN;
  process.env.OPENCODE_SERVER_URL = "http://opencode.internal:4096";
  process.env.OPENCODE_ALLOWED_HOSTS = "oc.freed.dev";
  delete process.env.GROQ_API_KEY;
  routes = {
    login: await import("../src/app/api/auth/login/route"),
    logout: await import("../src/app/api/auth/logout/route"),
    session: await import("../src/app/api/auth/session/route"),
    audit: await import("../src/app/api/security-audit/route"),
    reverse: await import("../src/app/api/reverse-engineering/route"),
    publish: await import("../src/app/api/github/publish/route"),
    credentials: await import("../src/app/api/credentials/route"),
    chat: await import("../src/app/api/chat/route"),
    models: await import("../src/app/api/models/route"),
  } as any;
  middleware = (await import("../src/middleware")).middleware as any;
});

function request(path: string, init: { method?: string; headers?: Record<string, string>; body?: BodyInit } = {}) {
  return new NextRequest(`${BASE}${path}`, { method: init.method || "GET", headers: { host: "lab.example", ...(init.headers || {}) }, body: init.body });
}

function setCookies(res: Response): string[] {
  return res.headers.getSetCookie();
}

function cookieValue(res: Response, name: string): string | undefined {
  const line = setCookies(res).find((c) => c.startsWith(`${name}=`));
  return line ? decodeURIComponent(line.split(";")[0].slice(name.length + 1)) : undefined;
}

async function login(ip = "10.9.9.9"): Promise<string> {
  const res = await routes.login.POST(request("/api/auth/login", { method: "POST", headers: { ...ORIGIN, "content-type": "application/json", "x-forwarded-for": ip }, body: JSON.stringify({ token: TOKEN }) }));
  assert.equal(res.status, 200);
  return `chl_session=${encodeURIComponent(cookieValue(res, "chl_session")!)}`;
}

function zipForm(bytes: Uint8Array, extra: Record<string, string> = {}) {
  const form = new FormData();
  form.append("archive", new File([bytes as BlobPart], "project.zip", { type: "application/zip" }));
  for (const [k, v] of Object.entries(extra)) form.append(k, v);
  return form;
}

test("sem APP_ACCESS_TOKEN tudo fica bloqueado (503) e a sessão informa o motivo", async () => {
  const saved = process.env.APP_ACCESS_TOKEN;
  delete process.env.APP_ACCESS_TOKEN;
  try {
    const mw = await middleware(request("/api/chat", { method: "POST", headers: ORIGIN }));
    assert.equal(mw.status, 503);
    const audit = await routes.audit.POST(request("/api/security-audit", { method: "POST", headers: ORIGIN, body: zipForm(await buildZip([{ name: "a.txt", data: "x" }])) }));
    assert.equal(audit.status, 503);
    const session = await (await routes.session.GET(request("/api/auth/session"))).json();
    assert.equal(session.configured, false);
  } finally {
    process.env.APP_ACCESS_TOKEN = saved;
  }
});

test("middleware: rota protegida sem sessão = 401; rota pública passa", async () => {
  assert.equal((await middleware(request("/api/skills"))).status, 401);
  assert.equal((await middleware(request("/api/github/publish", { method: "POST", headers: ORIGIN }))).status, 401);
  assert.equal((await middleware(request("/api/health"))).headers.get("x-middleware-next"), "1");
  assert.equal((await middleware(request("/api/auth/login", { method: "POST" }))).headers.get("x-middleware-next"), "1");
});

test("publicar no GitHub sem login agora é recusado (antes usava o GITHUB_TOKEN do servidor)", async () => {
  process.env.GITHUB_TOKEN = "ghp_fake_server_token_for_tests_only";
  const res = await routes.publish.POST(request("/api/github/publish", { method: "POST", headers: ORIGIN, body: zipForm(await buildZip([{ name: "a.txt", data: "x" }]), { repository: "victim/repo" }) }));
  assert.equal(res.status, 401);
});

test("login: token errado = 401, origem estranha = 403, correto = cookie HttpOnly/SameSite sem o token", async () => {
  const wrong = await routes.login.POST(request("/api/auth/login", { method: "POST", headers: { ...ORIGIN, "x-forwarded-for": "10.1.1.1" }, body: JSON.stringify({ token: "errado" }) }));
  assert.equal(wrong.status, 401);
  const cross = await routes.login.POST(request("/api/auth/login", { method: "POST", headers: { origin: "https://evil.example", "x-forwarded-for": "10.1.1.2" }, body: JSON.stringify({ token: TOKEN }) }));
  assert.equal(cross.status, 403);
  const ok = await routes.login.POST(request("/api/auth/login", { method: "POST", headers: { ...ORIGIN, "x-forwarded-for": "10.1.1.3" }, body: JSON.stringify({ token: TOKEN }) }));
  assert.equal(ok.status, 200);
  const line = setCookies(ok).find((c) => c.startsWith("chl_session="))!;
  assert.match(line, /HttpOnly/);
  assert.match(line, /SameSite=strict/);
  assert.equal(line.includes(TOKEN), false);
});

test("login: tentativas em excesso do mesmo IP recebem 429", async () => {
  let last = 0;
  for (let i = 0; i < 9; i++) {
    const res = await routes.login.POST(request("/api/auth/login", { method: "POST", headers: { ...ORIGIN, "x-forwarded-for": "10.2.2.2" }, body: JSON.stringify({ token: `errado-${i}` }) }));
    last = res.status;
  }
  assert.equal(last, 429);
});

test("sessão válida: auditoria funciona e o relatório traz hashes, confidence e status", async () => {
  const cookie = await login();
  const res = await routes.audit.POST(request("/api/security-audit", { method: "POST", headers: { ...ORIGIN, cookie }, body: zipForm(await buildZip([{ name: "src/a.js", data: "const c = { rejectUnauthorized: false };\n" }])) }));
  assert.equal(res.status, 200);
  const report = await res.json();
  assert.equal(report.schema, "cyberhuntlab.report/1.1");
  assert.match(report.integrity.archiveSha256, /^[0-9a-f]{64}$/);
  assert.equal(report.findings[0].status, "DETECTED");
  assert.equal(report.findings[0].confidence, "high");
  assert.equal(report.findings[0].line, 1);
});

test("sessão válida mas requisição de outra origem = 403 (CSRF)", async () => {
  const cookie = await login();
  const res = await routes.audit.POST(request("/api/security-audit", { method: "POST", headers: { origin: "https://evil.example", host: "lab.example", cookie }, body: zipForm(await buildZip([{ name: "a.txt", data: "x" }])) }));
  assert.equal(res.status, 403);
});

test("auditoria recusa ZIP bomb com tamanho forjado (413)", async () => {
  const cookie = await login();
  const bomb = forgeDeclaredSizes(await buildZip([{ name: "bomb.txt", data: new Uint8Array(8 * 1024 * 1024) }]), 128);
  const res = await routes.audit.POST(request("/api/security-audit", { method: "POST", headers: { ...ORIGIN, cookie }, body: zipForm(bomb) }));
  assert.equal(res.status, 413);
  assert.equal((await res.json()).code, "ZIP_BOMB");
});

test("auditoria, engenharia reversa e publicação recusam symlink (422)", async () => {
  const cookie = await login();
  const evil = await buildZip([{ name: "ok.txt", data: "ok" }, { name: "leak", data: "/etc/shadow", unixPermissions: 0o120777 }]);
  for (const [name, handler, extra] of [
    ["audit", routes.audit.POST, {}],
    ["reverse", routes.reverse.POST, {}],
    ["publish", routes.publish.POST, { repository: "owner/repo" }],
  ] as const) {
    const res = await handler(request("/api", { method: "POST", headers: { ...ORIGIN, cookie }, body: zipForm(evil, extra as Record<string, string>) }));
    assert.equal(res.status, 422, name);
    assert.equal((await res.json()).code, "SYMLINK", name);
  }
});

test("auditoria recusa travessia de diretório (422 UNSAFE_PATH)", async () => {
  const cookie = await login();
  const slip = renameEntry(await buildZip([{ name: "aaaevil.sh", data: "x" }]), "aaaevil.sh", "../evil.sh");
  const res = await routes.audit.POST(request("/api/security-audit", { method: "POST", headers: { ...ORIGIN, cookie }, body: zipForm(slip) }));
  assert.equal(res.status, 422);
  assert.equal((await res.json()).code, "UNSAFE_PATH");
});

test("cofre: URL OpenCode fora da allowlist é recusada; autorizada é cifrada sem expor a senha", async () => {
  const cookie = await login();
  const bad = await routes.credentials.POST(request("/api/credentials", { method: "POST", headers: { ...ORIGIN, cookie }, body: JSON.stringify({ kind: "opencode", url: "http://169.254.169.254/latest" }) }));
  assert.equal(bad.status, 400);
  const good = await routes.credentials.POST(request("/api/credentials", { method: "POST", headers: { ...ORIGIN, cookie }, body: JSON.stringify({ kind: "opencode", url: "https://oc.freed.dev", password: "senha-super-secreta" }) }));
  assert.equal(good.status, 200);
  const body = await good.text();
  assert.equal(body.includes("senha-super-secreta"), false);
  const vault = cookieValue(good, "chl_vault")!;
  assert.ok(vault.startsWith("v1."));
  assert.equal(vault.includes("senha"), false);
  assert.match(setCookies(good).find((c) => c.startsWith("chl_vault="))!, /HttpOnly/);
  const status = await (await routes.credentials.GET(request("/api/credentials", { headers: { cookie: `${cookie}; chl_vault=${encodeURIComponent(vault)}` } }))).json();
  assert.deepEqual(status.credentials.opencode, { url: "https://oc.freed.dev", hasPassword: true });
});

test("chat ignora customServerUrl injetado no corpo (anti-SSRF) e usa o servidor configurado", async () => {
  const cookie = await login();
  opencodeCalls.length = 0;
  await routes.chat.POST(request("/api/chat", {
    method: "POST",
    headers: { ...ORIGIN, cookie, "content-type": "application/json" },
    body: JSON.stringify({ message: "oi", model: "openai/gpt", customServerUrl: "http://169.254.169.254", customServerPassword: "x", userApiKeys: { groq: "gsk_x" } }),
  }));
  assert.deepEqual(opencodeCalls, ["http://opencode.internal:4096"]);
});

test("logout invalida o cookie de sessão", async () => {
  const cookie = await login();
  const res = await routes.logout.POST(request("/api/auth/logout", { method: "POST", headers: { ...ORIGIN, cookie }, body: "{}" }));
  assert.equal(res.status, 200);
  assert.match(setCookies(res).find((c) => c.startsWith("chl_session="))!, /Max-Age=0/);
});
