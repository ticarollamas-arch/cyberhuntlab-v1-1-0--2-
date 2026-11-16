/**
 * Guardas estáticas de regressão: impedem que uma rota nova ou alterada volte a abrir as falhas
 * corrigidas na v1.1 (rota sem autenticação, credencial vinda do navegador, SSRF, ZIP sem limite).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PUBLIC_API_PATHS } from "../src/lib/security/auth-core";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const apiDir = path.join(root, "src", "app", "api");

function routeFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return routeFiles(full);
    return name === "route.ts" ? [full] : [];
  });
}

function apiPath(file: string): string {
  return "/api/" + path.relative(apiDir, path.dirname(file)).split(path.sep).join("/");
}

const routes = routeFiles(apiDir).map((file) => ({ file, apiPath: apiPath(file), source: readFileSync(file, "utf8") }));

test("existem rotas para verificar", () => {
  assert.ok(routes.length >= 15, `encontradas ${routes.length}`);
});

test("toda rota não pública chama requireAuth em cada handler exportado", () => {
  for (const route of routes) {
    if (PUBLIC_API_PATHS.has(route.apiPath)) continue;
    const handlers = [...route.source.matchAll(/export async function (GET|POST|PUT|PATCH|DELETE)\s*\(/g)].map((m) => m[1]);
    assert.ok(handlers.length > 0, `${route.apiPath} não exporta handlers`);
    const delegated = /return handle\(req\)/.test(route.source) && /async function handle\(req: NextRequest\)[\s\S]*?requireAuth\(req\)/.test(route.source);
    for (const handler of handlers) {
      const body = route.source.split(new RegExp(`export async function ${handler}\\s*\\(`))[1].split(/\nexport async function /)[0];
      assert.ok(/await requireAuth\(req\)/.test(body) || delegated, `${handler} ${route.apiPath} não chama requireAuth`);
    }
  }
});

test("rotas públicas são só as esperadas e existem", () => {
  assert.deepEqual([...PUBLIC_API_PATHS].sort(), ["/api/auth/login", "/api/auth/session", "/api/health"]);
  for (const p of PUBLIC_API_PATHS) assert.ok(routes.some((r) => r.apiPath === p), `${p} não existe`);
});

test("o middleware cobre todo /api", () => {
  const middleware = readFileSync(path.join(root, "src", "middleware.ts"), "utf8");
  assert.match(middleware, /matcher:\s*\[\s*"\/api\/:path\*"\s*\]/);
  assert.match(middleware, /authorizeRequest\(/);
});

test("nenhuma rota aceita credenciais ou URLs de servidor vindas do navegador", () => {
  const forbidden = [
    /customServerUrl/, /customServerPassword/, /userApiKeys/, /groqApiKey/, /x-github-token/,
    /form\.get\(["']token["']\)/, /process\.env\.APP_ACCESS_TOKEN\s*&&/,
  ];
  for (const route of routes) for (const re of forbidden) assert.doesNotMatch(route.source, re, `${route.apiPath} contém ${re}`);
});

test("nenhuma rota descompacta ZIP sem o leitor seguro", () => {
  for (const route of routes) {
    assert.doesNotMatch(route.source, /JSZip\.loadAsync/, `${route.apiPath} usa JSZip.loadAsync diretamente`);
    assert.doesNotMatch(route.source, /_data\?*\.uncompressedSize/, `${route.apiPath} confia no tamanho declarado`);
  }
});

test("o frontend não guarda segredos no navegador nem os envia fora de /api/credentials", () => {
  const page = readFileSync(path.join(root, "src", "app", "page.tsx"), "utf8");
  // localStorage só recebe o estado de conversas (chave STORE); nenhuma credencial.
  const writes = [...page.matchAll(/localStorage\.setItem\(\s*([A-Za-z_"'-]+)/g)].map((m) => m[1]);
  assert.ok(writes.length > 0);
  for (const key of writes) assert.equal(key, "STORE", `localStorage.setItem com chave ${key}`);
  assert.doesNotMatch(page, /sessionStorage\.setItem\([^)]*(token|key|password)/i);
  // Nenhum envio de credencial no corpo de outras rotas.
  for (const re of [/userApiKeys/, /groqApiKey/, /x-github-token/, /append\(["']token["']/, /customServerUrl: apiKeys/, /customServerPassword: apiKeys/]) {
    assert.doesNotMatch(page, re, `page.tsx contém ${re}`);
  }
  // As chaves legadas são removidas do localStorage na migração.
  for (const legacy of ["LEGACY_API_KEYS", "LEGACY_GITHUB_TOKEN", "LEGACY_GITHUB_USER"]) {
    assert.match(page, new RegExp(`localStorage\\.removeItem\\(${legacy}\\)`));
  }
});
