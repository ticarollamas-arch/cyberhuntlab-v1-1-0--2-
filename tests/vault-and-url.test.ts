import { test } from "node:test";
import assert from "node:assert/strict";
import { describeVault, openVault, sealVault, sanitizeVault } from "../src/lib/security/vault-core";
import { checkUserOpencodeUrl, resolveOpencodeTarget } from "../src/lib/security/url-policy";

const TOKEN = "k".repeat(40);
const OTHER = "z".repeat(40);

test("cofre: cifra e decifra; o texto cifrado não revela a credencial", async () => {
  const sealed = await sealVault(TOKEN, { groq: "gsk_supersecret_value_123", github: "ghp_abcdefghijklmnopqrstuvwxyz0123" });
  assert.equal(sealed.includes("gsk_"), false);
  assert.equal(sealed.includes("ghp_"), false);
  const opened = await openVault(TOKEN, sealed);
  assert.equal(opened?.groq, "gsk_supersecret_value_123");
  assert.equal(opened?.github, "ghp_abcdefghijklmnopqrstuvwxyz0123");
});

test("cofre: cada selagem usa IV novo", async () => {
  const a = await sealVault(TOKEN, { groq: "x".repeat(20) });
  const b = await sealVault(TOKEN, { groq: "x".repeat(20) });
  assert.notEqual(a, b);
});

test("cofre: adulterado ou cifrado com outra chave retorna null", async () => {
  const sealed = await sealVault(TOKEN, { groq: "gsk_value_value_value" });
  const [v, iv, ct] = sealed.split(".");
  const flipped = ct.slice(0, 5) + (ct[5] === "A" ? "B" : "A") + ct.slice(6);
  assert.equal(await openVault(TOKEN, `${v}.${iv}.${flipped}`), null);
  assert.equal(await openVault(OTHER, sealed), null);
  assert.equal(await openVault(TOKEN, "v1.abc.def"), null);
  assert.equal(await openVault(TOKEN, undefined), null);
});

test("cofre: descarta campos desconhecidos e valores inválidos", () => {
  const clean = sanitizeVault({ groq: "  gsk_ok_value  ", evil: "x", github: 123, githubUser: { login: "../root" }, openai: "a".repeat(600) });
  assert.deepEqual(clean, { groq: "gsk_ok_value" });
});

test("cofre: resumo para o navegador não inclui valores", () => {
  const summary = describeVault({ groq: "gsk_secret", opencodeUrl: "https://oc.example", opencodePassword: "pw", github: "ghp_x", githubUser: { login: "freed" } });
  const text = JSON.stringify(summary);
  assert.equal(text.includes("gsk_secret"), false);
  assert.equal(text.includes("ghp_x"), false);
  assert.equal(text.includes("\"pw\""), false);
  assert.equal(summary.groq, true);
  assert.equal(summary.github.connected, true);
});

const env = { OPENCODE_SERVER_URL: "https://opencode.internal.example:4096", OPENCODE_SERVER_PASSWORD: "server-pw", OPENCODE_ALLOWED_HOSTS: "oc.freed.dev, 10.0.0.5:4096" };

test("SSRF: hosts fora da allowlist são recusados", () => {
  for (const url of [
    "http://169.254.169.254/latest/meta-data",
    "http://127.0.0.1:4096",
    "http://localhost:20128",
    "http://10.0.0.5:22",
    "https://evil.example",
    "file:///etc/passwd",
    "gopher://oc.freed.dev",
    "https://user:pass@oc.freed.dev",
    "https://oc.freed.dev/?x=1",
  ]) {
    assert.equal(checkUserOpencodeUrl(url, env).ok, false, url);
  }
});

test("SSRF: hosts autorizados e o próprio OPENCODE_SERVER_URL são aceitos", () => {
  assert.deepEqual(checkUserOpencodeUrl("https://oc.freed.dev/", env), { ok: true, url: "https://oc.freed.dev" });
  assert.equal(checkUserOpencodeUrl("http://10.0.0.5:4096", env).ok, true);
  assert.equal(checkUserOpencodeUrl("https://opencode.internal.example:4096", env).ok, true);
});

test("a senha do servidor não é enviada a outro host autorizado", () => {
  const other = resolveOpencodeTarget("https://oc.freed.dev", undefined, env);
  assert.equal(other.ok && other.password, undefined);
  const same = resolveOpencodeTarget("https://opencode.internal.example:4096", undefined, env);
  assert.equal(same.ok && same.password, "server-pw");
  const fallback = resolveOpencodeTarget(undefined, undefined, env);
  assert.deepEqual(fallback, { ok: true, baseUrl: "https://opencode.internal.example:4096", password: "server-pw", source: "server" });
});

test("sem allowlist, nenhuma URL do usuário é aceita", () => {
  const result = resolveOpencodeTarget("https://oc.freed.dev", "pw", {});
  assert.equal(result.ok, false);
});
