import { NextRequest, NextResponse } from "next/server";
import { constantTimeEqual, getAuthConfig, isSameOriginRequest, signSession } from "@/lib/security/auth-core";
import { AttemptLimiter } from "@/lib/security/rate-limit";
import { sessionCookie } from "@/lib/server/guard";

export const runtime = "nodejs";

const limiter = new AttemptLimiter(8, 15 * 60 * 1000);

function clientKey(req: NextRequest): string {
  return (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || req.headers.get("x-real-ip") || "local";
}

export async function POST(req: NextRequest) {
  const noStore = { "Cache-Control": "no-store" };
  if (!isSameOriginRequest({ method: req.method, pathname: req.nextUrl.pathname, header: (name) => req.headers.get(name) })) {
    return NextResponse.json({ error: "Origem não permitida." }, { status: 403, headers: noStore });
  }
  const config = getAuthConfig(process.env);
  if (!config.configured) {
    return NextResponse.json({ error: `Servidor bloqueado: ${config.reason}` }, { status: 503, headers: noStore });
  }
  const key = clientKey(req);
  const attempt = limiter.hit(key);
  if (!attempt.allowed) {
    return NextResponse.json(
      { error: `Muitas tentativas. Aguarde ${attempt.retryAfterSeconds} segundos.` },
      { status: 429, headers: { ...noStore, "Retry-After": String(attempt.retryAfterSeconds) } },
    );
  }
  const body = await req.json().catch(() => ({}));
  const token = typeof body?.token === "string" ? body.token.trim() : "";
  if (!token || !constantTimeEqual(token, config.token)) {
    return NextResponse.json({ error: "Token de acesso inválido." }, { status: 401, headers: noStore });
  }
  limiter.reset(key);
  const res = NextResponse.json({ ok: true, authenticated: true }, { headers: noStore });
  res.cookies.set(sessionCookie(req, await signSession(config.token, Math.floor(Date.now() / 1000))));
  return res;
}
