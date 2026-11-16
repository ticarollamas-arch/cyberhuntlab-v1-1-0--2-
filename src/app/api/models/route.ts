import { NextRequest, NextResponse } from "next/server";
import { fetchNineRouterModels, getNineRouterConfig } from "@/lib/ninerouter";
import { basicAuthHeader, opencodeTargetFor, readVault, requireAuth } from "@/lib/server/guard";

export const runtime = "nodejs";

async function readCatalog(baseUrl: string, password?: string) {
  const headers: Record<string, string> = basicAuthHeader(password);

  let providers: any[] = [];
  let connected: string[] = [];
  let openCodeError = "";
  try {
    const response = await fetch(`${baseUrl}/provider`, { headers, cache: "no-store", redirect: "error", signal: AbortSignal.timeout(9000) });
    if (!response.ok) throw new Error(`OpenCode respondeu ${response.status}`);
    const payload = await response.json();
    connected = payload.connected || [];
    const authResponse = await fetch(`${baseUrl}/provider/auth`, { headers, cache: "no-store", redirect: "error", signal: AbortSignal.timeout(9000) }).catch(() => null);
    const authMethods = authResponse?.ok ? await authResponse.json() : {};
    providers = (payload.all || []).map((provider: any) => ({
      id: provider.id,
      name: provider.name || provider.id,
      connected: connected.includes(provider.id),
      authMethods: authMethods[provider.id] || [],
      models: Object.entries(provider.models || {}).map(([id, model]: [string, any]) => ({
        id, name: model.name || id, context: model.limit?.context || null, output: model.limit?.output || null,
        inputPrice: model.cost?.input ?? null, outputPrice: model.cost?.output ?? null,
        free: (provider.id === "opencode" || provider.id === "opencode-go") ? model.cost?.input === 0 : model.cost?.input === 0 && model.cost?.output === 0,
        modalities: model.modalities || null,
      })),
    })).filter((provider: any) => provider.models.length > 0);
  } catch (error) {
    openCodeError = error instanceof Error ? error.message : "OpenCode indisponível";
  }

  let router: any = { configured: false, connected: false, models: [] };
  if (getNineRouterConfig().configured) {
    try {
      const routed = await fetchNineRouterModels();
      router = { configured: true, connected: true, models: routed.models, defaultModel: getNineRouterConfig().defaultCombo || null };
      if (routed.models.length) providers.unshift({
        id: "9router", name: "9Router · Rotação automática", connected: true, authMethods: [], models: routed.models,
      });
    } catch (error) {
      router = { configured: true, connected: false, models: [], error: error instanceof Error ? error.message : "Falha ao consultar 9Router." };
    }
  }
  return NextResponse.json({ providers, connected, source: "OpenCode + 9Router", router, openCodeError });
}

// O servidor OpenCode consultado vem do cofre do servidor ou da configuração padrão.
// URLs enviadas no corpo são ignoradas (proteção contra SSRF).
async function handle(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  try {
    const target = opencodeTargetFor(await readVault(req));
    if (!target.ok) return NextResponse.json({ providers: [], connected: [], error: target.error }, { status: 400 });
    return await readCatalog(target.baseUrl, target.password);
  } catch (error) {
    return NextResponse.json({ providers: [], connected: [], error: error instanceof Error ? error.message : "Não foi possível consultar o catálogo." }, { status: 503 });
  }
}

export async function GET(req: NextRequest) {
  return handle(req);
}

export async function POST(req: NextRequest) {
  return handle(req);
}
