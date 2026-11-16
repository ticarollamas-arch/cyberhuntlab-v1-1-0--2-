import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE, VAULT_COOKIE } from "@/lib/security/auth-core";
import { cookieOptions, requireAuth } from "@/lib/server/guard";

export const runtime = "nodejs";

/** Encerra a sessão. Com `{ "forgetCredentials": true }`, apaga também o cofre de credenciais. */
export async function POST(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  const body = await req.json().catch(() => ({}));
  const res = NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  res.cookies.set(SESSION_COOKIE, "", cookieOptions(req, 0));
  if (body?.forgetCredentials === true) res.cookies.set(VAULT_COOKIE, "", cookieOptions(req, 0));
  return res;
}
