import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { normalizeEntryPath, openSafeZip, ZipSecurityError, type ZipLimits } from "../src/lib/security/safe-zip";
import { buildZip, forgeDeclaredSizes, renameEntry } from "./helpers/zip-fixtures";

const LIMITS: ZipLimits = { maxArchiveBytes: 3 * 1024 * 1024, maxEntries: 50, maxTotalBytes: 1024 * 1024, maxEntryBytes: 512 * 1024 };

async function rejects(promise: Promise<unknown>, code: string) {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof ZipSecurityError, `esperava ZipSecurityError, veio ${String(error)}`);
    assert.equal(error.code, code, error.message);
    return true;
  });
}

async function readAll(bytes: Uint8Array, limits = LIMITS) {
  const zip = await openSafeZip(bytes, limits);
  for (const entry of zip.entries) await zip.readBytes(entry);
  return zip;
}

test("ZIP legítimo: lê conteúdo e calcula SHA-256 correto", async () => {
  const bytes = await buildZip([{ name: "app/index.js", data: "console.log('ok');\n" }, { name: "app/README.md", data: "# demo\n" }]);
  const zip = await openSafeZip(bytes, LIMITS);
  assert.deepEqual(zip.entries.map((e) => e.path).sort(), ["app/README.md", "app/index.js"]);
  assert.equal(zip.archiveSha256, createHash("sha256").update(bytes).digest("hex"));
  const entry = zip.entries.find((e) => e.path === "app/index.js")!;
  assert.equal(await zip.readText(entry), "console.log('ok');\n");
});

test("ZIP bomb: tamanho declarado forjado como pequeno é detectado pela contagem real", async () => {
  const payload = new Uint8Array(900 * 1024); // 900 KB de zeros: comprime para ~1 KB
  const honest = await buildZip([{ name: "bomb.txt", data: payload }]);
  assert.ok(honest.byteLength < 10 * 1024, "o fixture precisa ser altamente compressível");
  const forged = forgeDeclaredSizes(honest, 100);
  const zip = await openSafeZip(forged, LIMITS);
  assert.equal(zip.entries[0].declaredSize, 100, "o cabeçalho mente sobre o tamanho");
  await rejects(zip.readBytes(zip.entries[0]), "ZIP_BOMB");
  assert.ok(zip.bytesRead <= LIMITS.maxEntryBytes, "a leitura parou no limite, sem descompactar tudo");
});

test("ZIP bomb: soma de várias entradas excede o orçamento total", async () => {
  const chunk = new Uint8Array(400 * 1024);
  const bytes = await buildZip([1, 2, 3, 4].map((n) => ({ name: `part${n}.bin`, data: chunk })));
  await rejects(readAll(bytes), "ZIP_BOMB");
});

test("tamanhos declarados forjados: a análise para na primeira entrada e nunca passa do orçamento", async () => {
  const chunk = new Uint8Array(400 * 1024);
  const forged = forgeDeclaredSizes(await buildZip([1, 2, 3, 4].map((n) => ({ name: `p${n}.bin`, data: chunk }))), 10);
  const zip = await openSafeZip(forged, LIMITS);
  let rejectedAt = -1;
  for (let i = 0; i < zip.entries.length; i++) {
    try { await zip.readBytes(zip.entries[i]); } catch (error) {
      assert.ok(error instanceof ZipSecurityError && ["SIZE_MISMATCH", "ZIP_BOMB"].includes(error.code));
      rejectedAt = i;
      break;
    }
  }
  assert.equal(rejectedAt, 0, "a primeira entrada adulterada já interrompe a leitura");
  assert.ok(zip.bytesRead <= LIMITS.maxTotalBytes);
});

test("tamanho real maior que o declarado, mesmo dentro dos limites, é tratado como adulteração", async () => {
  const forged = forgeDeclaredSizes(await buildZip([{ name: "a.txt", data: "x".repeat(5000) }]), 10);
  const zip = await openSafeZip(forged, { ...LIMITS, maxEntryBytes: 4096 });
  await rejects(zip.readBytes(zip.entries[0]), "ZIP_BOMB");
  const zip2 = await openSafeZip(forged, LIMITS);
  await rejects(zip2.readBytes(zip2.entries[0]), "SIZE_MISMATCH");
});

test("entrada que declara tamanho acima do limite é recusada antes de descompactar", async () => {
  const bytes = await buildZip([{ name: "big.bin", data: new Uint8Array(600 * 1024) }]);
  const zip = await openSafeZip(bytes, LIMITS);
  await rejects(zip.readBytes(zip.entries[0]), "ENTRY_TOO_LARGE");
  assert.equal(zip.bytesRead, 0);
});

test("link simbólico rejeita o ZIP inteiro", async () => {
  const bytes = await buildZip([
    { name: "ok.txt", data: "ok" },
    { name: "link-to-etc", data: "/etc/passwd", unixPermissions: 0o120777 },
  ]);
  await rejects(openSafeZip(bytes, LIMITS), "SYMLINK");
});

test("link simbólico apontando para fora do projeto (../) também é rejeitado", async () => {
  const bytes = await buildZip([{ name: "src/config", data: "../../../../root/.ssh/id_rsa", unixPermissions: 0o120755 }]);
  await rejects(openSafeZip(bytes, LIMITS), "SYMLINK");
});

test("arquivo comum com permissões normais não é confundido com symlink", async () => {
  const bytes = await buildZip([{ name: "run.sh", data: "#!/bin/sh\n", unixPermissions: 0o100755 }]);
  const zip = await openSafeZip(bytes, LIMITS);
  assert.equal(zip.entries.length, 1);
});

test("travessia de diretório (ZIP Slip) é rejeitada", async () => {
  const bytes = renameEntry(await buildZip([{ name: "aa/evil.sh", data: "x" }]), "aa/evil.sh", "../evil.sh");
  await rejects(openSafeZip(bytes, LIMITS), "UNSAFE_PATH");
});

test("caminho absoluto e letra de unidade são rejeitados", async () => {
  const absolute = renameEntry(await buildZip([{ name: "xetc/passwd", data: "x" }]), "xetc/passwd", "/etc/passwd");
  await rejects(openSafeZip(absolute, LIMITS), "UNSAFE_PATH");
  const drive = renameEntry(await buildZip([{ name: "abwin.ini", data: "x" }]), "abwin.ini", "C:win.ini");
  await rejects(openSafeZip(drive, LIMITS), "UNSAFE_PATH");
});

test("travessia com barra invertida (estilo Windows) é rejeitada", async () => {
  const bytes = renameEntry(await buildZip([{ name: "aaaevil.txt", data: "x" }]), "aaaevil.txt", "..\\evil.txt");
  await rejects(openSafeZip(bytes, LIMITS), "UNSAFE_PATH");
});

test("caminhos duplicados por maiúsculas/minúsculas são rejeitados", async () => {
  const bytes = await buildZip([{ name: "README.md", data: "a" }, { name: "readme.md", data: "b" }]);
  await rejects(openSafeZip(bytes, LIMITS), "DUPLICATE_PATH");
});

test("excesso de entradas é recusado", async () => {
  const bytes = await buildZip(Array.from({ length: 60 }, (_, i) => ({ name: `f${i}.txt`, data: "x" })));
  await rejects(openSafeZip(bytes, LIMITS), "TOO_MANY_ENTRIES");
});

test("arquivo grande demais e arquivo que não é ZIP são recusados", async () => {
  await rejects(openSafeZip(new Uint8Array(LIMITS.maxArchiveBytes + 1), LIMITS), "ARCHIVE_TOO_LARGE");
  await rejects(openSafeZip(new TextEncoder().encode("não sou um zip"), LIMITS), "INVALID_ARCHIVE");
  await rejects(openSafeZip(new Uint8Array(0), LIMITS), "INVALID_ARCHIVE");
});

test("normalizeEntryPath", () => {
  assert.equal(normalizeEntryPath("./a//b/./c.txt"), "a/b/c.txt");
  assert.equal(normalizeEntryPath("a\\b.txt"), "a/b.txt");
  for (const bad of ["../a", "a/../../b", "/a", "C:/a", "c:a", "a\u0000b", "//server/share", "", ".", "./"]) {
    assert.equal(normalizeEntryPath(bad), null, JSON.stringify(bad));
  }
});
