import { NextRequest, NextResponse } from "next/server";
import { basicAuthHeader, opencodeTargetFor, readVault, requireAuth } from "@/lib/server/guard";

export const runtime = "nodejs";

/**
 * Envia a API key de um provedor ao cofre de autenticação do servidor OpenCode (PUT /auth/:id).
 * O destino vem do cofre do CyberHuntLab ou da configuração do servidor, nunca do corpo (anti-SSRF).
 */
export async function PUT(req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  try {
    const { id } = await context.params;
    const { key } = await req.json();
    if (!/^[a-zA-Z0-9._-]{1,64}$/.test(id) || typeof key !== "string" || key.trim().length < 8 || key.length > 1024) {
      return NextResponse.json({ error: "Provedor ou credencial inválida." }, { status: 400 });
    }
    const target = opencodeTargetFor(await readVault(req));
    if (!target.ok) return NextResponse.json({ error: target.error }, { status: 400 });
    const response = await fetch(`${target.baseUrl}/auth/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...basicAuthHeader(target.password) },
      body: JSON.stringify({ type: "api", key: key.trim() }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 500);
      return NextResponse.json({ error: detail || `OpenCode recusou a credencial (${response.status}).` }, { status: response.status });
    }
    return NextResponse.json({ ok: true, provider: id, message: "Credencial enviada ao servidor OpenCode." });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Falha ao conectar provedor." }, { status: 502 });
  }
}
