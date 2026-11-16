import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/server/guard";

export const runtime = "nodejs";

// Valida um token informado explicitamente. Não há mais fallback para GITHUB_TOKEN do servidor:
// antes, uma chamada sem token devolvia os dados da conta GitHub da administração.
// Para conectar o GitHub ao CyberHuntLab use POST /api/credentials { kind: "github" }.
export async function POST(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  try {
    const body = await req.json().catch(() => ({}));
    const token = body.token;

    if (!token || typeof token !== "string" || !token.trim()) {
      return NextResponse.json(
        { ok: false, error: "Nenhum token fornecido." },
        { status: 400 }
      );
    }

    const cleanToken = token.trim();

    const res = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${cleanToken}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "OpenCode-Workspace",
      },
    });

    if (!res.ok) {
      if (res.status === 401) {
        return NextResponse.json(
          { ok: false, error: "Token inválido ou expirado. Verifique a chave inserida." },
          { status: 401 }
        );
      }
      return NextResponse.json(
        { ok: false, error: `GitHub API respondeu com status ${res.status}.` },
        { status: res.status }
      );
    }

    const user = await res.json();
    return NextResponse.json({
      ok: true,
      user: {
        login: user.login,
        name: user.name || user.login,
        avatar_url: user.avatar_url,
        html_url: user.html_url,
        public_repos: user.public_repos,
        total_private_repos: user.total_private_repos,
      },
    });
  } catch (error) {
    return NextResponse.json(
      { ok: false, error: error instanceof Error ? error.message : "Erro ao validar token." },
      { status: 500 }
    );
  }
}
