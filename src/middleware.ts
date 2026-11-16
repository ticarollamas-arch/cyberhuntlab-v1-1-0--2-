import { NextRequest, NextResponse } from "next/server";
import { authorizeRequest } from "@/lib/security/auth-core";

/**
 * Portão central do CyberHuntLab: toda rota sob /api exige sessão válida ou x-app-token,
 * exceto as rotas públicas listadas em PUBLIC_API_PATHS. Sem APP_ACCESS_TOKEN, responde 503.
 */
export async function middleware(req: NextRequest) {
  const decision = await authorizeRequest(
    { method: req.method, pathname: req.nextUrl.pathname, header: (name) => req.headers.get(name) },
    { APP_ACCESS_TOKEN: process.env.APP_ACCESS_TOKEN },
    Math.floor(Date.now() / 1000),
  );
  if (decision.ok) return NextResponse.next();
  return NextResponse.json({ error: decision.error, code: "AUTH_REQUIRED" }, { status: decision.status, headers: { "Cache-Control": "no-store" } });
}

export const config = { matcher: ["/api/:path*"] };
