/**
 * CyberHuntLab — política de destino para servidores OpenCode (proteção contra SSRF).
 *
 * Antes da v1.1, o navegador podia enviar qualquer `customServerUrl` e o servidor fazia requisições
 * para esse endereço (inclusive 127.0.0.1, rede interna da VPS e metadados de nuvem). Agora um
 * servidor OpenCode personalizado só é aceito se o host estiver em OPENCODE_ALLOWED_HOSTS ou for o
 * mesmo host de OPENCODE_SERVER_URL.
 */

export const DEFAULT_OPENCODE_URL = "http://127.0.0.1:4096";

export type UrlPolicyEnv = {
  OPENCODE_SERVER_URL?: string;
  OPENCODE_SERVER_PASSWORD?: string;
  OPENCODE_ALLOWED_HOSTS?: string;
  [key: string]: string | undefined;
};

export type OpencodeTarget = { ok: true; baseUrl: string; password?: string; source: "server" | "user" } | { ok: false; error: string };

function parseHttpUrl(value: string): URL | null {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    return url;
  } catch {
    return null;
  }
}

export function allowedOpencodeHosts(env: UrlPolicyEnv): Set<string> {
  const hosts = new Set<string>();
  for (const raw of (env.OPENCODE_ALLOWED_HOSTS || "").split(",")) {
    const host = raw.trim().toLowerCase();
    if (host) hosts.add(host);
  }
  const server = env.OPENCODE_SERVER_URL ? parseHttpUrl(env.OPENCODE_SERVER_URL) : null;
  if (server) hosts.add(server.host.toLowerCase());
  return hosts;
}

/** Valida uma URL informada pelo usuário. Retorna a URL normalizada ou uma mensagem de erro. */
export function checkUserOpencodeUrl(value: string, env: UrlPolicyEnv): { ok: true; url: string } | { ok: false; error: string } {
  const url = parseHttpUrl(value);
  if (!url) return { ok: false, error: "URL do servidor OpenCode inválida. Use http(s)://host[:porta], sem usuário e senha na URL." };
  if (url.search || url.hash) return { ok: false, error: "A URL do servidor OpenCode não pode conter query string ou fragmento." };
  const allowed = allowedOpencodeHosts(env);
  if (!allowed.has(url.host.toLowerCase())) {
    return {
      ok: false,
      error: `Host '${url.host}' não está autorizado. A administração precisa incluí-lo em OPENCODE_ALLOWED_HOSTS (proteção contra SSRF).`,
    };
  }
  return { ok: true, url: `${url.origin}${url.pathname.replace(/\/+$/, "")}` };
}

/**
 * Decide para qual servidor OpenCode o backend deve se conectar.
 * - Sem URL do usuário: usa OPENCODE_SERVER_URL (ou o padrão local) com a senha do servidor.
 * - Com URL do usuário: exige host autorizado. A senha do servidor só é enviada se a origem for
 *   exatamente a mesma de OPENCODE_SERVER_URL; caso contrário usa apenas a senha do usuário.
 */
export function resolveOpencodeTarget(userUrl: string | undefined, userPassword: string | undefined, env: UrlPolicyEnv): OpencodeTarget {
  const serverUrl = (env.OPENCODE_SERVER_URL || DEFAULT_OPENCODE_URL).replace(/\/+$/, "");
  if (!userUrl || !userUrl.trim()) {
    return { ok: true, baseUrl: serverUrl, password: env.OPENCODE_SERVER_PASSWORD || undefined, source: "server" };
  }
  const checked = checkUserOpencodeUrl(userUrl, env);
  if (!checked.ok) return checked;
  const sameAsServer = parseHttpUrl(serverUrl)?.origin === parseHttpUrl(checked.url)?.origin;
  const password = userPassword || (sameAsServer ? env.OPENCODE_SERVER_PASSWORD : undefined) || undefined;
  return { ok: true, baseUrl: checked.url, password, source: "user" };
}
