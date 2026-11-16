/**
 * Implementação mínima de next/server para executar os handlers reais das rotas nos testes.
 * Cobre apenas o que as rotas do CyberHuntLab usam: nextUrl, cookies.get, NextResponse.json,
 * NextResponse.next e cookies.set (gera cabeçalhos Set-Cookie).
 */
type CookieOptions = { httpOnly?: boolean; secure?: boolean; sameSite?: string; path?: string; maxAge?: number };

export class NextRequest extends Request {
  readonly nextUrl: URL;
  readonly cookies: { get(name: string): { name: string; value: string } | undefined };
  constructor(input: string, init?: RequestInit) {
    super(input, init);
    this.nextUrl = new URL(input);
    const header = this.headers.get("cookie") || "";
    const jar = new Map<string, string>();
    for (const part of header.split(";")) {
      const i = part.indexOf("=");
      if (i > 0) jar.set(part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim()));
    }
    this.cookies = { get: (name) => (jar.has(name) ? { name, value: jar.get(name)! } : undefined) };
  }
}

export class NextResponse extends Response {
  readonly cookies = {
    set: (nameOrCookie: string | ({ name: string; value: string } & CookieOptions), value?: string, options?: CookieOptions) => {
      const cookie = typeof nameOrCookie === "string" ? { name: nameOrCookie, value: value ?? "", ...(options || {}) } : nameOrCookie;
      const parts = [`${cookie.name}=${encodeURIComponent(cookie.value)}`];
      if (cookie.path) parts.push(`Path=${cookie.path}`);
      if (cookie.maxAge !== undefined) parts.push(`Max-Age=${cookie.maxAge}`);
      if (cookie.httpOnly) parts.push("HttpOnly");
      if (cookie.secure) parts.push("Secure");
      if (cookie.sameSite) parts.push(`SameSite=${cookie.sameSite}`);
      this.headers.append("set-cookie", parts.join("; "));
    },
  };
  static json(body: unknown, init?: ResponseInit) {
    const headers = new Headers(init?.headers);
    headers.set("content-type", "application/json");
    return new NextResponse(JSON.stringify(body), { ...init, headers });
  }
  static next() {
    return new NextResponse(null, { status: 200, headers: { "x-middleware-next": "1" } });
  }
}
