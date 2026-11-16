/**
 * CyberHuntLab — cofre de credenciais.
 *
 * As credenciais do usuário (Groq, GitHub, OpenCode privado...) são cifradas com AES-256-GCM no
 * servidor e guardadas num cookie HttpOnly. O navegador só armazena texto cifrado e o JavaScript da
 * página não consegue lê-lo. A chave é derivada de APP_ACCESS_TOKEN e nunca sai do servidor.
 *
 * Sem dependências de Next.js ou Node: Web Crypto apenas.
 */

export const VAULT_MAX_COOKIE_LENGTH = 3800;

export type VaultData = {
  groq?: string;
  openai?: string;
  anthropic?: string;
  gemini?: string;
  github?: string;
  githubUser?: { login: string; name?: string; avatar_url?: string; html_url?: string; public_repos?: number };
  opencodeUrl?: string;
  opencodePassword?: string;
};

const SECRET_STRING_FIELDS = ["groq", "openai", "anthropic", "gemini", "github", "opencodeUrl", "opencodePassword"] as const;
export type VaultStringField = (typeof SECRET_STRING_FIELDS)[number];

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

async function vaultKey(token: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", encoder.encode(token), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const raw = await crypto.subtle.sign("HMAC", base, encoder.encode("cyberhuntlab/v1/vault"));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/** Mantém somente campos conhecidos, com tipos e tamanhos válidos. */
export function sanitizeVault(input: unknown): VaultData {
  const out: VaultData = {};
  if (!input || typeof input !== "object") return out;
  const source = input as Record<string, unknown>;
  for (const field of SECRET_STRING_FIELDS) {
    const value = source[field];
    if (typeof value === "string" && value.trim() && value.length <= 512) out[field] = value.trim();
  }
  const user = source.githubUser as Record<string, unknown> | undefined;
  if (user && typeof user === "object" && typeof user.login === "string" && /^[A-Za-z0-9-]{1,39}$/.test(user.login)) {
    out.githubUser = {
      login: user.login,
      name: typeof user.name === "string" ? user.name.slice(0, 120) : undefined,
      avatar_url: typeof user.avatar_url === "string" && user.avatar_url.startsWith("https://") ? user.avatar_url.slice(0, 300) : undefined,
      html_url: typeof user.html_url === "string" && user.html_url.startsWith("https://github.com/") ? user.html_url.slice(0, 200) : undefined,
      public_repos: typeof user.public_repos === "number" ? user.public_repos : undefined,
    };
  }
  return out;
}

/** Formato: v1.<iv>.<texto cifrado + tag>. */
export async function sealVault(token: string, data: VaultData): Promise<string> {
  const clean = sanitizeVault(data);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode("chl_vault/v1") },
    await vaultKey(token),
    encoder.encode(JSON.stringify(clean)),
  );
  const sealed = `v1.${b64url(iv)}.${b64url(new Uint8Array(cipher))}`;
  if (sealed.length > VAULT_MAX_COOKIE_LENGTH) throw new Error("O cofre de credenciais excede o tamanho máximo de cookie.");
  return sealed;
}

/** Retorna null se o valor estiver ausente, adulterado ou cifrado com outra chave. */
export async function openVault(token: string, value: string | undefined | null): Promise<VaultData | null> {
  if (!value || value.length > VAULT_MAX_COOKIE_LENGTH) return null;
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const iv = unb64url(parts[1]);
  const cipher = unb64url(parts[2]);
  if (!iv || iv.length !== 12 || !cipher || cipher.length < 17) return null;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: encoder.encode("chl_vault/v1") },
      await vaultKey(token),
      cipher as BufferSource,
    );
    return sanitizeVault(JSON.parse(decoder.decode(plain)));
  } catch {
    return null;
  }
}

/** Resumo seguro para o navegador: indica o que está configurado, sem revelar valores. */
export function describeVault(data: VaultData) {
  return {
    groq: Boolean(data.groq),
    openai: Boolean(data.openai),
    anthropic: Boolean(data.anthropic),
    gemini: Boolean(data.gemini),
    github: data.github ? { connected: true, user: data.githubUser || null } : { connected: false, user: null },
    opencode: data.opencodeUrl ? { url: data.opencodeUrl, hasPassword: Boolean(data.opencodePassword) } : null,
  };
}
