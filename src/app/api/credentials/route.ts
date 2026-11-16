import { NextRequest, NextResponse } from "next/server";
import { describeVault, type VaultData } from "@/lib/security/vault-core";
import { checkUserOpencodeUrl } from "@/lib/security/url-policy";
import { readVault, requireAuth, writeVault } from "@/lib/server/guard";

export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store" };
const KINDS = ["groq", "openai", "anthropic", "gemini", "github", "opencode"] as const;
type Kind = (typeof KINDS)[number];

function isKind(value: unknown): value is Kind {
  return typeof value === "string" && (KINDS as readonly string[]).includes(value);
}

async function verifyGroq(key: string): Promise<string | null> {
  const response = await fetch("https://api.groq.com/openai/v1/models", {
    headers: { Authorization: `Bearer ${key}` },
    cache: "no-store",
    signal: AbortSignal.timeout(10000),
  }).catch(() => null);
  if (!response) return "Não foi possível contatar a Groq para validar a chave.";
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    return payload?.error?.message || `A Groq recusou a chave (${response.status}).`;
  }
  return null;
}

async function verifyGithub(token: string): Promise<{ error: string } | { user: NonNullable<VaultData["githubUser"]> }> {
  const response = await fetch("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "CyberHuntLab" },
    cache: "no-store",
    signal: AbortSignal.timeout(10000),
  }).catch(() => null);
  if (!response) return { error: "Não foi possível contatar o GitHub para validar o token." };
  if (response.status === 401) return { error: "Token do GitHub inválido ou expirado." };
  if (!response.ok) return { error: `GitHub respondeu com status ${response.status}.` };
  const user = await response.json();
  return { user: { login: user.login, name: user.name || user.login, avatar_url: user.avatar_url, html_url: user.html_url, public_repos: user.public_repos } };
}

/** Lista o que está configurado, sem nunca devolver valores. */
export async function GET(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  return NextResponse.json({ credentials: describeVault(await readVault(req)) }, { headers: NO_STORE });
}

/** Salva uma credencial no cofre cifrado (cookie HttpOnly). Valida Groq e GitHub antes de salvar. */
export async function POST(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  const body = await req.json().catch(() => ({}));
  const kind = body?.kind;
  if (!isKind(kind)) return NextResponse.json({ error: `Tipo de credencial inválido. Use: ${KINDS.join(", ")}.` }, { status: 400, headers: NO_STORE });

  const vault = await readVault(req);
  const value = typeof body.value === "string" ? body.value.trim() : "";

  if (kind === "opencode") {
    const url = typeof body.url === "string" ? body.url.trim() : "";
    if (!url) return NextResponse.json({ error: "Informe a URL do servidor OpenCode." }, { status: 400, headers: NO_STORE });
    const checked = checkUserOpencodeUrl(url, process.env);
    if (!checked.ok) return NextResponse.json({ error: checked.error }, { status: 400, headers: NO_STORE });
    vault.opencodeUrl = checked.url;
    const password = typeof body.password === "string" ? body.password : "";
    if (password) vault.opencodePassword = password;
    else if (body.clearPassword === true) delete vault.opencodePassword;
  } else {
    if (value.length < 8 || value.length > 512) {
      return NextResponse.json({ error: "Credencial vazia ou com tamanho inválido." }, { status: 400, headers: NO_STORE });
    }
    if (kind === "groq") {
      const error = await verifyGroq(value);
      if (error) return NextResponse.json({ error }, { status: 400, headers: NO_STORE });
      vault.groq = value;
    } else if (kind === "github") {
      const result = await verifyGithub(value);
      if ("error" in result) return NextResponse.json({ error: result.error }, { status: 400, headers: NO_STORE });
      vault.github = value;
      vault.githubUser = result.user;
    } else {
      // OpenAI, Anthropic e Gemini ainda não são consumidas pelas rotas; ficam guardadas para a fase de IA.
      vault[kind as "openai" | "anthropic" | "gemini"] = value;
    }
  }

  const res = NextResponse.json({ ok: true, credentials: describeVault(vault) }, { headers: NO_STORE });
  await writeVault(req, res, vault);
  return res;
}

/** Remove uma credencial (`?kind=groq`) ou todas (`?kind=all`). */
export async function DELETE(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  const kind = req.nextUrl.searchParams.get("kind");
  let vault = await readVault(req);
  if (kind === "all") vault = {};
  else if (kind === "github") { delete vault.github; delete vault.githubUser; }
  else if (kind === "opencode") { delete vault.opencodeUrl; delete vault.opencodePassword; }
  else if (isKind(kind)) delete vault[kind as "groq" | "openai" | "anthropic" | "gemini"];
  else return NextResponse.json({ error: "Tipo de credencial inválido." }, { status: 400, headers: NO_STORE });
  const res = NextResponse.json({ ok: true, credentials: describeVault(vault) }, { headers: NO_STORE });
  await writeVault(req, res, vault);
  return res;
}
