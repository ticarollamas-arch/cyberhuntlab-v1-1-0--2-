/**
 * Geradores de ZIPs maliciosos para os testes. Todos os dados são sintéticos.
 */
import JSZip from "jszip";

export async function buildZip(
  files: Array<{ name: string; data: string | Uint8Array; unixPermissions?: number; dir?: boolean }>,
  platform: "UNIX" | "DOS" = "UNIX",
): Promise<Uint8Array> {
  const zip = new JSZip();
  for (const file of files) {
    if (file.dir) zip.folder(file.name);
    else zip.file(file.name, file.data, { unixPermissions: file.unixPermissions, createFolders: false });
  }
  return zip.generateAsync({ type: "uint8array", compression: "DEFLATE", compressionOptions: { level: 9 }, platform });
}

/**
 * Reescreve o "tamanho descompactado" declarado de todas as entradas, no cabeçalho local e no
 * diretório central. Simula um atacante que mente sobre o tamanho para burlar limites ingênuos.
 */
export function forgeDeclaredSizes(zipBytes: Uint8Array, fakeSize: number): Uint8Array {
  const out = new Uint8Array(zipBytes);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (let i = 0; i + 46 <= out.length; i++) {
    const signature = view.getUint32(i, true);
    if (signature === 0x04034b50) view.setUint32(i + 22, fakeSize, true);
    else if (signature === 0x02014b50) view.setUint32(i + 24, fakeSize, true);
  }
  return out;
}

/** Renomeia uma entrada byte a byte (mesmo comprimento) para criar nomes que o JSZip não geraria. */
export function renameEntry(zipBytes: Uint8Array, from: string, to: string): Uint8Array {
  if (from.length !== to.length) throw new Error("renameEntry exige nomes de mesmo comprimento");
  const out = new Uint8Array(zipBytes);
  const needle = new TextEncoder().encode(from);
  const replacement = new TextEncoder().encode(to);
  for (let i = 0; i + needle.length <= out.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) if (out[i + j] !== needle[j]) { match = false; break; }
    if (match) out.set(replacement, i);
  }
  return out;
}
