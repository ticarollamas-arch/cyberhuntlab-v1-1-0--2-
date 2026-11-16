/**
 * Helpers de servidor (Next.js) para autenticação e cofre de credenciais.
 *
 * Defesa em profundidade: o middleware já bloqueia /api/*, e cada rota protegida chama
 * `requireAuth` novamente. Um teste estático garante que nenhuma rota esqueça essa chamada.
 */
import { NextRequest, NextResponse } from "next/server";
import { authorizeRequest, getAuthConfig, SESSION_COOKIE, SESSION_TTL_SECONDS, VAULT_COOKIE } from "@/lib/security/auth-core";
import { openVault, sealVault, type VaultData } from "@/lib/security/vault-core";
import { resolveOpencodeTarget, type OpencodeTarget } from "@/lib/security/url-policy";

export async function requireAuth(req: NextRequest): Promise<NextResponse | null> {
  const decision = await authorizeRequest(
    { method: req.method, pathname: req.nextUrl.pathname, header: (name) => req.headers.get(name) },
    process.env,
    Math.floor(Date.now() / 1000),
  );
  if (decision.ok) return null;
  return NextResponse.json({ error: decision.error, code: "AUTH_REQUIRED" }, { status: decision.status, headers: { "Cache-Control": "no-store" } });
}

function secureCookies(req: NextRequest): boolean {
  if (process.env.NODE_ENV === "production") return true;
  return req.nextUrl.protocol === "https:" || req.headers.get("x-forwarded-proto") === "https";
}

export function cookieOptions(req: NextRequest, maxAge: number) {
  return { httpOnly: true, secure: secureCookies(req), sameSite: "strict" as const, path: "/", maxAge };
}

function serverToken(): string {
  const config = getAuthConfig(process.env);
  if (!config.configured) throw new Error(config.reason);
  return config.token;
}

export async function readVault(req: NextRequest): Promise<VaultData> {
  const config = getAuthConfig(process.env);
  if (!config.configured) return {};
  return (await openVault(config.token, req.cookies.get(VAULT_COOKIE)?.value)) || {};
}

export async function writeVault(req: NextRequest, res: NextResponse, data: VaultData): Promise<void> {
  const empty = !Object.keys(data).length;
  if (empty) {
    res.cookies.set(VAULT_COOKIE, "", cookieOptions(req, 0));
    return;
  }
  res.cookies.set(VAULT_COOKIE, await sealVault(serverToken(), data), cookieOptions(req, 30 * 24 * 60 * 60));
}

export function sessionCookie(req: NextRequest, value: string) {
  return { name: SESSION_COOKIE, value, ...cookieOptions(req, SESSION_TTL_SECONDS) };
}

/** Destino OpenCode para esta requisição: servidor padrão ou o servidor privado salvo no cofre. */
export function opencodeTargetFor(vault: VaultData): OpencodeTarget {
  return resolveOpencodeTarget(vault.opencodeUrl, vault.opencodePassword, process.env);
}

export function basicAuthHeader(password?: string): Record<string, string> {
  return password ? { Authorization: `Basic ${Buffer.from(`opencode:${password}`).toString("base64")}` } : {};
}
