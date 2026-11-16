import { NextRequest, NextResponse } from "next/server";
import { authorizeRequest, getAuthConfig } from "@/lib/security/auth-core";

export const runtime = "nodejs";

/** Rota pública: informa se o servidor está configurado e se a sessão atual é válida. */
export async function GET(req: NextRequest) {
  const config = getAuthConfig(process.env);
  if (!config.configured) {
    return NextResponse.json({ configured: false, authenticated: false, reason: config.reason }, { headers: { "Cache-Control": "no-store" } });
  }
  // Avalia como se fosse uma rota protegida, para reutilizar exatamente a mesma regra.
  const decision = await authorizeRequest(
    { method: "GET", pathname: "/api/__session_probe", header: (name) => req.headers.get(name) },
    process.env,
    Math.floor(Date.now() / 1000),
  );
  return NextResponse.json({ configured: true, authenticated: decision.ok }, { headers: { "Cache-Control": "no-store" } });
}
