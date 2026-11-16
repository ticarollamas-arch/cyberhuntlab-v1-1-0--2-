/**
 * CyberHuntLab — leitura segura de arquivos ZIP enviados por usuários.
 *
 * Garantias:
 *  - Limites de tamanho medidos nos bytes REALMENTE descompactados (via stream), não no tamanho
 *    declarado no cabeçalho do ZIP, que pode ser forjado. Isso bloqueia ZIP bombs.
 *  - Entradas cujo tamanho real difere do declarado são tratadas como adulteração.
 *  - Links simbólicos, caminhos absolutos, travessia (`..`), letras de unidade, bytes de controle e
 *    caminhos duplicados (inclusive por maiúsculas/minúsculas) rejeitam o arquivo inteiro.
 *  - Nada é gravado em disco e nenhum conteúdo é executado.
 *
 * Observação: o JSZip ≥ 3.8 já "limpa" nomes com `..` e guarda o original em `unsafeOriginalName`.
 * Verificamos o nome original, para recusar o arquivo em vez de aceitá-lo silenciosamente.
 */
import JSZip from "jszip";
import { createHash } from "node:crypto";

export type ZipErrorCode =
  | "INVALID_ARCHIVE"
  | "ARCHIVE_TOO_LARGE"
  | "TOO_MANY_ENTRIES"
  | "SYMLINK"
  | "UNSAFE_PATH"
  | "DUPLICATE_PATH"
  | "ZIP_BOMB"
  | "SIZE_MISMATCH"
  | "ENTRY_TOO_LARGE";

export class ZipSecurityError extends Error {
  readonly code: ZipErrorCode;
  readonly path?: string;
  constructor(code: ZipErrorCode, message: string, path?: string) {
    super(message);
    this.name = "ZipSecurityError";
    this.code = code;
    this.path = path;
  }
}

export type ZipLimits = {
  /** Tamanho máximo do arquivo .zip compactado. */
  maxArchiveBytes: number;
  /** Número máximo de entradas (arquivos + diretórios) no diretório central. */
  maxEntries: number;
  /** Soma máxima de bytes realmente descompactados durante toda a análise. */
  maxTotalBytes: number;
  /** Tamanho máximo real de uma única entrada lida. */
  maxEntryBytes: number;
};

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxArchiveBytes: 3 * 1024 * 1024,
  maxEntries: 1500,
  maxTotalBytes: 24 * 1024 * 1024,
  maxEntryBytes: 4 * 1024 * 1024,
};

export type SafeZipEntry = {
  /** Caminho normalizado, sempre relativo e com `/`. */
  path: string;
  declaredSize: number;
  compressedSize: number;
  object: JSZip.JSZipObject;
};

const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Normaliza e valida um caminho de entrada. Retorna null se o caminho for inseguro. */
export function normalizeEntryPath(raw: string): string | null {
  if (typeof raw !== "string" || !raw) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(raw)) return null;
  const path = raw.replace(/\\/g, "/");
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path) || path.startsWith("//")) return null;
  const segments: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") return null;
    segments.push(segment);
  }
  return segments.length ? segments.join("/") : null;
}

function isSymlink(object: JSZip.JSZipObject): boolean {
  const mode = (object as unknown as { unixPermissions?: number | string | null }).unixPermissions;
  const numeric = typeof mode === "string" ? parseInt(mode, 8) : mode;
  return typeof numeric === "number" && Number.isFinite(numeric) && (numeric & S_IFMT) === S_IFLNK;
}

function sizes(object: JSZip.JSZipObject): { declared: number; compressed: number } {
  const data = (object as unknown as { _data?: { uncompressedSize?: number; compressedSize?: number } })._data;
  return { declared: Number(data?.uncompressedSize) || 0, compressed: Number(data?.compressedSize) || 0 };
}

function streamWithCap(object: JSZip.JSZipObject, cap: number): Promise<{ bytes: Uint8Array; exceeded: boolean; seen: number }> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let seen = 0;
    let settled = false;
    // internalStream é API pública do JSZip 3, mas não consta nas definições de tipo oficiais.
    type StreamHelper = { on(event: string, cb: (...args: any[]) => void): StreamHelper; pause(): StreamHelper; resume(): StreamHelper };
    const stream = (object as unknown as { internalStream(type: "uint8array"): StreamHelper }).internalStream("uint8array");
    stream.on("data", (chunk: Uint8Array) => {
      if (settled) return;
      seen += chunk.byteLength;
      if (seen > cap) {
        settled = true;
        stream.pause();
        resolve({ bytes: new Uint8Array(0), exceeded: true, seen });
        return;
      }
      chunks.push(chunk);
    });
    stream.on("error", (error: Error) => {
      if (settled) return;
      settled = true;
      // O próprio JSZip compara o tamanho real com o declarado ao final do stream.
      if (/size mismatch/i.test(error.message)) {
        reject(new ZipSecurityError("SIZE_MISMATCH", `Entrada '${object.name}' tem tamanho real diferente do declarado. Arquivo adulterado ou corrompido.`, object.name));
        return;
      }
      reject(new ZipSecurityError("INVALID_ARCHIVE", `Falha ao descompactar entrada: ${error.message}`));
    });
    stream.on("end", () => {
      if (settled) return;
      settled = true;
      const out = new Uint8Array(seen);
      let offset = 0;
      for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
      resolve({ bytes: out, exceeded: false, seen });
    });
    stream.resume();
  });
}

export type SafeZip = {
  limits: ZipLimits;
  archiveSha256: string;
  archiveBytes: number;
  /** Somente arquivos (diretórios omitidos), já validados. */
  entries: SafeZipEntry[];
  /** Total de bytes reais descompactados até o momento. */
  readonly bytesRead: number;
  /** Lê uma entrada respeitando o limite por arquivo e o orçamento global. */
  readBytes(entry: SafeZipEntry, maxBytes?: number): Promise<Uint8Array>;
  /** Lê como UTF-8; retorna null se parecer binário (contém byte NUL). */
  readText(entry: SafeZipEntry, maxBytes?: number): Promise<string | null>;
};

export async function openSafeZip(input: Uint8Array | ArrayBuffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): Promise<SafeZip> {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.byteLength === 0) throw new ZipSecurityError("INVALID_ARCHIVE", "Arquivo ZIP vazio.");
  if (bytes.byteLength > limits.maxArchiveBytes) {
    throw new ZipSecurityError("ARCHIVE_TOO_LARGE", `ZIP com ${bytes.byteLength} bytes excede o limite de ${limits.maxArchiveBytes} bytes.`);
  }

  let zip: JSZip;
  try {
    // checkCRC32 continua desativado: verificar CRC no carregamento descompactaria tudo de uma vez.
    zip = await JSZip.loadAsync(bytes, { checkCRC32: false, createFolders: false });
  } catch (error) {
    throw new ZipSecurityError("INVALID_ARCHIVE", `Arquivo ZIP inválido: ${error instanceof Error ? error.message : "formato não reconhecido"}.`);
  }

  const objects = Object.values(zip.files);
  if (objects.length > limits.maxEntries) {
    throw new ZipSecurityError("TOO_MANY_ENTRIES", `O ZIP tem ${objects.length} entradas; o limite é ${limits.maxEntries}.`);
  }

  const entries: SafeZipEntry[] = [];
  const seenPaths = new Map<string, string>();
  for (const object of objects) {
    const original = (object as unknown as { unsafeOriginalName?: string }).unsafeOriginalName ?? object.name;
    const path = normalizeEntryPath(original);
    if (!path || normalizeEntryPath(object.name) !== path) {
      throw new ZipSecurityError("UNSAFE_PATH", `Caminho inseguro no ZIP: '${String(original).slice(0, 200)}'.`, String(original));
    }
    if (isSymlink(object)) {
      throw new ZipSecurityError("SYMLINK", `Link simbólico não é permitido no ZIP: '${path}'.`, path);
    }
    const key = path.toLowerCase();
    if (seenPaths.has(key)) {
      throw new ZipSecurityError("DUPLICATE_PATH", `Caminho duplicado no ZIP: '${path}' conflita com '${seenPaths.get(key)}'.`, path);
    }
    seenPaths.set(key, path);
    if (object.dir) continue;
    const { declared, compressed } = sizes(object);
    entries.push({ path, declaredSize: declared, compressedSize: compressed, object });
  }

  let bytesRead = 0;
  const safe: SafeZip = {
    limits,
    archiveSha256: sha256Hex(bytes),
    archiveBytes: bytes.byteLength,
    entries,
    get bytesRead() { return bytesRead; },
    async readBytes(entry, maxBytes = limits.maxEntryBytes) {
      const perEntry = Math.min(maxBytes, limits.maxEntryBytes);
      const remaining = limits.maxTotalBytes - bytesRead;
      if (entry.declaredSize > perEntry) {
        throw new ZipSecurityError("ENTRY_TOO_LARGE", `Entrada '${entry.path}' declara ${entry.declaredSize} bytes; o limite é ${perEntry}.`, entry.path);
      }
      if (entry.declaredSize > remaining) {
        throw new ZipSecurityError("ZIP_BOMB", `Conteúdo descompactado excederia o orçamento total de ${limits.maxTotalBytes} bytes.`, entry.path);
      }
      const cap = Math.min(perEntry, remaining);
      const result = await streamWithCap(entry.object, cap);
      if (result.exceeded) {
        bytesRead += cap;
        throw new ZipSecurityError(
          "ZIP_BOMB",
          `Entrada '${entry.path}' descompactou além de ${cap} bytes embora declare ${entry.declaredSize}. Possível ZIP bomb ou cabeçalho forjado.`,
          entry.path,
        );
      }
      bytesRead += result.seen;
      if (result.seen !== entry.declaredSize) {
        throw new ZipSecurityError(
          "SIZE_MISMATCH",
          `Entrada '${entry.path}' tem ${result.seen} bytes reais, mas declara ${entry.declaredSize}. Arquivo adulterado ou corrompido.`,
          entry.path,
        );
      }
      return result.bytes;
    },
    async readText(entry, maxBytes) {
      const data = await safe.readBytes(entry, maxBytes);
      if (data.includes(0)) return null;
      return new TextDecoder("utf-8", { fatal: false }).decode(data);
    },
  };
  return safe;
}

/** Converte erros em resposta HTTP coerente (413 para limites, 422 para conteúdo recusado). */
export function zipErrorStatus(error: ZipSecurityError): number {
  switch (error.code) {
    case "ARCHIVE_TOO_LARGE":
    case "TOO_MANY_ENTRIES":
    case "ZIP_BOMB":
    case "ENTRY_TOO_LARGE":
      return 413;
    default:
      return 422;
  }
}
