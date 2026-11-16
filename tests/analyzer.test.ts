import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { analyzeArchive, REPORT_SCHEMA } from "../src/lib/audit/analyzer";
import { applyStatusChange, FINDING_STATUSES } from "../src/lib/audit/findings";
import { openSafeZip, DEFAULT_ZIP_LIMITS, ZipSecurityError } from "../src/lib/security/safe-zip";
import { buildZip, forgeDeclaredSizes } from "./helpers/zip-fixtures";

// Dados sintéticos: os "segredos" abaixo são fictícios e existem apenas para acionar as regras.
const FAKE_GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP";

async function report(files: Array<{ name: string; data: string }>) {
  const bytes = await buildZip(files);
  return { bytes, report: await analyzeArchive(await openSafeZip(bytes, DEFAULT_ZIP_LIMITS), "demo.zip", new Date("2026-11-16T12:00:00Z")) };
}

test("relatório traz schema, hash do ZIP e SHA-256 correto por arquivo", async () => {
  const content = "export const ok = true;\n";
  const { bytes, report: r } = await report([{ name: "src/ok.ts", data: content }]);
  assert.equal(r.schema, REPORT_SCHEMA);
  assert.equal(r.integrity.archiveSha256, createHash("sha256").update(bytes).digest("hex"));
  assert.deepEqual(r.integrity.files, [{ path: "src/ok.ts", sha256: createHash("sha256").update(content).digest("hex"), bytes: content.length }]);
});

test("todo achado automático nasce DETECTED, com confidence, linha e hash do arquivo", async () => {
  const code = `const a = 1;\nconst token = "${FAKE_GH}";\nconst agent = { rejectUnauthorized: false };\n`;
  const { report: r } = await report([{ name: "src/client.js", data: code }]);
  assert.ok(r.findings.length >= 2);
  const fileHash = r.integrity.files[0].sha256;
  for (const f of r.findings) {
    assert.equal(f.status, "DETECTED");
    assert.equal(f.origin, "automated");
    assert.ok(["high", "medium", "low"].includes(f.confidence));
    assert.equal(f.history[0].by, "analyzer");
  }
  const gh = r.findings.find((f) => f.ruleId === "CHL-SECRET-GITHUB")!;
  assert.equal(gh.line, 2);
  assert.equal(gh.confidence, "high");
  assert.equal(gh.fileSha256, fileHash);
  assert.equal(gh.cwe, "CWE-798");
  const tls = r.findings.find((f) => f.ruleId === "CHL-TLS-DISABLED")!;
  assert.equal(tls.line, 3);
  assert.equal(r.summary.statusCounts.DETECTED, r.findings.length);
  assert.equal(r.summary.statusCounts.VALIDATED, 0);
});

test("um segredo específico não gera duplicata pela regra genérica na mesma linha", async () => {
  const { report: r } = await report([{ name: "a.js", data: `const token = "${FAKE_GH}";\n` }]);
  const secretFindings = r.findings.filter((f) => f.category === "Segredos");
  assert.equal(secretFindings.length, 1);
  assert.equal(secretFindings[0].ruleId, "CHL-SECRET-GITHUB");
});

test("regras de grupos diferentes na mesma linha geram achados separados (antes só o primeiro aparecia)", async () => {
  const { report: r } = await report([{ name: "a.js", data: `const c = { rejectUnauthorized: false, key: "${FAKE_AWS}" };\n` }]);
  const ids = r.findings.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, ["CHL-SECRET-AWS", "CHL-TLS-DISABLED"]);
});

test("o relatório nunca reproduz o valor do segredo", async () => {
  const { report: r } = await report([{ name: ".github/x.yml", data: `key: ${FAKE_AWS}\ntoken: "${FAKE_GH}"\n` }]);
  const text = JSON.stringify(r);
  assert.equal(text.includes(FAKE_GH), false);
  assert.equal(text.includes(FAKE_AWS), false);
});

test("arquivos sensíveis não são lidos nem hasheados", async () => {
  const { report: r } = await report([{ name: ".env", data: `TOKEN=${FAKE_GH}` }, { name: ".env.example", data: "TOKEN=" }]);
  assert.equal(r.summary.skippedSensitive, 1);
  assert.equal(r.findings.length, 0);
  assert.ok(r.integrity.notHashed.some((n) => n.path === ".env"));
  assert.ok(r.integrity.files.some((f) => f.path === ".env.example"));
});

test("confiança baixa para heurísticas e alta para padrões específicos", async () => {
  const { report: r } = await report([
    { name: "x.js", data: "eval(userInput);\n" },
    { name: "Dockerfile", data: "FROM node:latest\nUSER root\n" },
  ]);
  assert.equal(r.findings.find((f) => f.ruleId === "CHL-EXEC-DYNAMIC")?.confidence, "low");
  assert.equal(r.findings.find((f) => f.ruleId === "CHL-DOCKER-LATEST")?.confidence, "high");
  assert.equal(r.findings.find((f) => f.ruleId === "CHL-DOCKER-ROOT")?.line, 2);
});

test("ZIP bomb durante a auditoria interrompe a análise com erro de segurança", async () => {
  const forged = forgeDeclaredSizes(await buildZip([{ name: "big.txt", data: "A".repeat(6 * 1024 * 1024) }]), 64);
  const zip = await openSafeZip(forged, DEFAULT_ZIP_LIMITS);
  await assert.rejects(analyzeArchive(zip, "bomb.zip"), (e: unknown) => e instanceof ZipSecurityError && e.code === "ZIP_BOMB");
});

test("pesquisador muda o estado com histórico; DETECTED é reservado ao analisador", async () => {
  const { report: r } = await report([{ name: "a.js", data: "eval(x)\n" }]);
  const original = r.findings[0];
  const changed = applyStatusChange(original, "FALSE_POSITIVE", "  entrada é constante  ", new Date("2026-11-17T00:00:00Z"));
  assert.equal(changed.status, "FALSE_POSITIVE");
  assert.equal(changed.history.length, 2);
  assert.deepEqual(changed.history[1], { status: "FALSE_POSITIVE", at: "2026-11-17T00:00:00.000Z", by: "researcher", note: "entrada é constante" });
  assert.equal(original.status, "DETECTED", "o achado original não é mutado");
  assert.throws(() => applyStatusChange(original, "DETECTED"));
  assert.throws(() => applyStatusChange(original, "HACKED" as never));
  assert.equal(FINDING_STATUSES.length, 6);
});
