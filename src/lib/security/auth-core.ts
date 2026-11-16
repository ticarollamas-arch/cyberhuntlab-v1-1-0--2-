/**
 * CyberHuntLab — núcleo de autenticação.
 *
 * Este módulo não importa Next.js nem APIs exclusivas do Node: usa apenas Web Crypto,
 * TextEncoder e btoa/atob. Assim roda no middleware (Edge), nas rotas (Node) e nos testes.
 *
 * Política: fail-closed. Sem APP_ACCESS_TOKEN válido no servidor, nenhuma rota protegida responde.
 */

export const SESSION_COOKIE = "chl_session";
export const VAULT_COOKIE = "chl_vault";
export const SESSION_TTL_SECONDS = 12 * 60 * 60;
export const MIN_TOKEN_LENGTH = 32;

/** Rotas acessíveis sem sessão. Qualquer outra rota sob /api exige autenticação. */
export const PUBLIC_API_PATHS = new Set<string>(["/api/health", "/api/auth/login", "/api/auth/session"]);

// A assinatura de índice torna o tipo compatível com process.env (NodeJS.ProcessEnv do Next.js).
export type AuthEnv = { APP_ACCESS_TOKEN?: string; [key: string]: string | undefined };

export type AuthConfig =
  | { configured: true; token: string }
  | { configured: false; reason: string };

export function getAuthConfig(env: AuthEnv): AuthConfig {
  const token = (env.APP_ACCESS_TOKEN || "").trim();
  if (!token) return { configured: false, reason: "APP_ACCESS_TOKEN não está definido no servidor." };
  if (token.length < MIN_TOKEN_LENGTH) {
    return { configured: false, reason: `APP_ACCESS_TOKEN precisa ter pelo menos ${MIN_TOKEN_LENGTH} caracteres.` };
  }
  return { configured: true, token };
}

const encoder = new TextEncoder();

/** Comparação em tempo constante em relação ao conteúdo (o comprimento pode vazar). */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/**
 * Deriva material de chave independente por finalidade ("session", "vault") a partir do token.
 * Trocar APP_ACCESS_TOKEN invalida todas as sessões e todos os cofres de credenciais.
 */
export async function deriveKeyBytes(token: string, purpose: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(token), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const out = await crypto.subtle.sign("HMAC", key, encoder.encode(`cyberhuntlab/v1/${purpose}`));
  return new Uint8Array(out);
}

async function hmac(token: string, payload: string): Promise<string> {
  const raw = await deriveKeyBytes(token, "session");
  const key = await crypto.subtle.importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return toBase64Url(new Uint8Array(sig));
}

/** Formato: v1.<expiraEmSegundos>.<assinatura>. O cookie nunca contém o token. */
export async function signSession(token: string, nowSeconds: number, ttlSeconds = SESSION_TTL_SECONDS): Promise<string> {
  const payload = `v1.${Math.floor(nowSeconds) + ttlSeconds}`;
  return `${payload}.${await hmac(token, payload)}`;
}

export async function verifySession(token: string, value: string | undefined | null, nowSeconds: number): Promise<boolean> {
  if (!value || value.length > 256) return false;
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== "v1" || !/^\d{1,12}$/.test(parts[1])) return false;
  const expiresAt = Number(parts[1]);
  if (!Number.isFinite(expiresAt) || expiresAt <= nowSeconds) return false;
  // Rejeita sessões com validade maior que o TTL máximo (assinadas com outra política).
  if (expiresAt - nowSeconds > SESSION_TTL_SECONDS + 60) return false;
  const expected = await hmac(token, `${parts[0]}.${parts[1]}`);
  return constantTimeEqual(expected, parts[2]);
}

export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const piece of header.split(";")) {
    const index = piece.indexOf("=");
    if (index <= 0) continue;
    const name = piece.slice(0, index).trim();
    const value = piece.slice(index + 1).trim();
    if (name && !(name in out)) {
      try { out[name] = decodeURIComponent(value); } catch { out[name] = value; }
    }
  }
  return out;
}

export type AuthRequest = {
  method: string;
  pathname: string;
  /** Leitura de cabeçalho insensível a maiúsculas (Headers.get). */
  header: (name: string) => string | null;
};

export type AuthDecision =
  | { ok: true; via: "public" | "header" | "session" }
  | { ok: false; status: 401 | 403 | 503; error: string };

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function hostOf(value: string | null): string | null {
  if (!value) return null;
  try { return new URL(value).host.toLowerCase(); } catch { return null; }
}

/**
 * Proteção CSRF para requisições autenticadas por cookie: métodos que alteram estado precisam vir
 * da mesma origem. Requisições autenticadas por cabeçalho (x-app-token) não sofrem CSRF, pois o
 * navegador não envia cabeçalhos personalizados entre origens sem preflight.
 */
export function isSameOriginRequest(req: AuthRequest): boolean {
  const host = (req.header("x-forwarded-host") || req.header("host") || "").split(",")[0].trim().toLowerCase();
  if (!host) return false;
  const origin = req.header("origin");
  if (origin) return hostOf(origin) === host;
  const fetchSite = req.header("sec-fetch-site");
  if (fetchSite) return fetchSite === "same-origin";
  const referer = req.header("referer");
  if (referer) return hostOf(referer) === host;
  // Sem nenhum indício de origem: navegadores modernos sempre enviam Origin em POST/PUT/DELETE.
  return false;
}

export async function authorizeRequest(req: AuthRequest, env: AuthEnv, nowSeconds: number): Promise<AuthDecision> {
  const pathname = req.pathname.replace(/\/+$/, "") || "/";
  if (PUBLIC_API_PATHS.has(pathname)) return { ok: true, via: "public" };

  const config = getAuthConfig(env);
  if (!config.configured) {
    return { ok: false, status: 503, error: `CyberHuntLab bloqueado: ${config.reason} Configure o token para liberar o acesso.` };
  }

  const headerToken = req.header("x-app-token");
  if (headerToken) {
    return constantTimeEqual(headerToken, config.token)
      ? { ok: true, via: "header" }
      : { ok: false, status: 401, error: "Token de acesso inválido." };
  }

  const session = parseCookies(req.header("cookie"))[SESSION_COOKIE];
  if (!(await verifySession(config.token, session, nowSeconds))) {
    return { ok: false, status: 401, error: "Sessão ausente ou expirada. Faça login no CyberHuntLab." };
  }
  if (!SAFE_METHODS.has(req.method.toUpperCase()) && !isSameOriginRequest(req)) {
    return { ok: false, status: 403, error: "Requisição bloqueada: origem diferente da aplicação (proteção CSRF)." };
  }
  return { ok: true, via: "session" };
}
