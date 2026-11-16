/**
 * CyberHuntLab — analisador estático de projetos ZIP (v1.1).
 *
 * Cada achado automatizado traz:
 *  - severity: impacto indicativo se o achado for real;
 *  - confidence: quão provável é que a regra tenha acertado (alta = padrão específico; baixa =
 *    heurística que exige leitura humana do contexto);
 *  - status: estado de validação. Achados automáticos SEMPRE nascem como DETECTED. Somente o
 *    pesquisador pode movê-los para VALIDATED ou FALSE_POSITIVE.
 *  - evidência com arquivo, linha e SHA-256 do arquivo, sem reproduzir valores de segredos.
 */
import { sha256Hex, type SafeZip } from "../security/safe-zip";

export const ANALYZER_VERSION = "1.1.0";
export const REPORT_SCHEMA = "cyberhuntlab.report/1.1";

import type { Confidence, Finding, FindingStatus, Severity } from "./findings";
import { FINDING_STATUSES } from "./findings";

export type { Confidence, Finding, FindingStatus, Severity };

type LineRule = {
  id: string;
  re: RegExp;
  severity: Severity;
  confidence: Confidence;
  title: string;
  evidence: string;
  recommendation: string;
  category: string;
  cwe: string | null;
  /** Regras do mesmo grupo são exclusivas na mesma linha: vale a primeira (mais específica). */
  group?: string;
};

const LINE_RULES: LineRule[] = [
  { id: "CHL-SECRET-AWS", group: "secret", re: /\bAKIA[0-9A-Z]{16}\b/, severity: "critical", confidence: "high", title: "Possível AWS Access Key exposta", evidence: "Padrão compatível com chave AWS; valor ocultado.", recommendation: "Revogue/rotacione a credencial e use secret manager.", category: "Segredos", cwe: "CWE-798" },
  { id: "CHL-SECRET-GITHUB", group: "secret", re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/, severity: "critical", confidence: "high", title: "Possível token GitHub exposto", evidence: "Padrão compatível com token GitHub; valor ocultado.", recommendation: "Revogue o token, revise auditoria e use secret manager.", category: "Segredos", cwe: "CWE-798" },
  { id: "CHL-SECRET-PRIVKEY", group: "secret", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, severity: "critical", confidence: "high", title: "Chave privada incluída no código", evidence: "Cabeçalho de chave privada detectado.", recommendation: "Remova do pacote/histórico e gere uma nova chave.", category: "Segredos", cwe: "CWE-321" },
  { id: "CHL-SECRET-DEFAULT", group: "secret", re: /(?:password|passwd|secret|token)\s*[:=]\s*["'](?:changeme|password|admin|123456|test)["']/i, severity: "high", confidence: "medium", title: "Credencial padrão/fraca", evidence: "Valor conhecido como padrão encontrado.", recommendation: "Substitua por segredo forte e único.", category: "Segredos", cwe: "CWE-1392" },
  { id: "CHL-SECRET-GENERIC", group: "secret", re: /(?:api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"'\s]{12,}["']/i, severity: "high", confidence: "low", title: "Possível segredo hardcoded", evidence: "Atribuição com aparência de credencial; valor ocultado.", recommendation: "Confirme se é segredo real, rotacione e use variável segura.", category: "Segredos", cwe: "CWE-798" },
  { id: "CHL-TLS-DISABLED", re: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False)/i, severity: "high", confidence: "high", title: "Validação TLS desativada", evidence: "Configuração pode aceitar certificados não confiáveis.", recommendation: "Reative validação TLS e configure certificados corretamente.", category: "Criptografia", cwe: "CWE-295" },
  { id: "CHL-EXEC-DYNAMIC", re: /(?:\beval\s*\(|new Function\s*\(|child_process\.(?:exec|execSync)\s*\()/, severity: "medium", confidence: "low", title: "Execução dinâmica/comando de sistema", evidence: "Padrão de execução encontrado; o fluxo de dados até ele não foi analisado.", recommendation: "Não passe entrada não confiável; use allowlists e APIs sem shell.", category: "Execução", cwe: "CWE-95" },
  { id: "CHL-CORS-WILDCARD", re: /(?:Access-Control-Allow-Origin["']?\s*[:=,]\s*["']\*["']|cors\s*\(\s*\{[^}]*origin\s*:\s*["']\*["'])/i, severity: "medium", confidence: "medium", title: "CORS permissivo", evidence: "Configuração de origem curinga detectada.", recommendation: "Restrinja CORS às origens necessárias.", category: "Web", cwe: "CWE-942" },
  { id: "CHL-DEBUG-ON", re: /(?:\bdebug\s*[:=]\s*true\b|\bDEBUG\s*=\s*True\b)/, severity: "medium", confidence: "low", title: "Modo debug habilitado", evidence: "Configuração debug=true encontrada.", recommendation: "Desative debug em produção e evite stack traces públicos.", category: "Configuração", cwe: "CWE-489" },
];

const SKIP = /(^|\/)(node_modules|\.git|\.next|dist|build|coverage|vendor|\.venv|venv)(\/|$)/i;
const SENSITIVE = /(^|\/)\.env(?:$|\.(?!example$)[^/]+$)|(^|\/)(.*\.(?:pem|key|p12|pfx)|id_rsa|id_ed25519|credentials\.json|\.npmrc|\.pypirc)$/i;
const TEXT = /\.(?:json|ya?ml|toml|ini|conf|config|properties|md|txt|js|jsx|ts|tsx|mjs|cjs|py|go|rs|java|kt|php|rb|sh|bash|tf|hcl|xml|html|sql)$/i;
const DOCKERFILE = /(^|\/)Dockerfile(?:\.[^/]*)?$/i;
const MAX_TEXT = 500 * 1024;
const MAX_FINDINGS_PER_RULE_AND_FILE = 20;

export type AuditReport = ReturnType<typeof buildReport>;

function detectFramework(paths: string[], pkg: any) {
  const d = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
  if (d.next) return "Next.js"; if (d["@angular/core"]) return "Angular"; if (d.vue) return "Vue.js"; if (d["@remix-run/react"]) return "Remix";
  if (d.react && d.vite) return "React + Vite"; if (d.react) return "React"; if (d.express) return "Node.js + Express";
  if (paths.some((x) => /(^|\/)go\.mod$/i.test(x))) return "Go"; if (paths.some((x) => /Cargo\.toml$/i.test(x))) return "Rust";
  if (paths.some((x) => /requirements\.txt$|pyproject\.toml$/i.test(x))) return "Python"; if (paths.some((x) => /pom\.xml$|build\.gradle/i.test(x))) return "Java / JVM";
  if (paths.some((x) => /\.tf$/i.test(x))) return "Terraform / IaC"; if (paths.some((x) => /Chart\.yaml$|kustomization\.ya?ml$/i.test(x))) return "Kubernetes / Helm";
  return "Não identificado";
}

function lineOf(content: string, re: RegExp): number | null {
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return null;
}

export async function analyzeArchive(zip: SafeZip, fileName: string, now = new Date()) {
  const findings: Finding[] = [];
  const paths: string[] = [];
  const deps: Record<string, string> = {};
  const hashes: { path: string; sha256: string; bytes: number }[] = [];
  const notHashed: { path: string; reason: string }[] = [];
  const inventory = { kubernetes: [] as string[], docker: [] as string[], terraform: [] as string[], python: [] as string[], vercel: false };
  let pkg: any = null;
  let textFiles = 0;
  let skippedSensitive = 0;
  const analyzedAt = now.toISOString();

  const add = (rule: Omit<LineRule, "re" | "group">, file: string, line: number | null, fileSha256: string | null, extraEvidence?: string) => {
    findings.push({
      id: `F-${String(findings.length + 1).padStart(3, "0")}`,
      ruleId: rule.id,
      severity: rule.severity,
      confidence: rule.confidence,
      status: "DETECTED",
      origin: "automated",
      title: rule.title,
      file,
      line,
      fileSha256,
      evidence: `${line ? `Linha ${line}: ` : ""}${extraEvidence || rule.evidence}`,
      recommendation: rule.recommendation,
      category: rule.category,
      cwe: rule.cwe,
      history: [{ status: "DETECTED", at: analyzedAt, by: "analyzer" }],
    });
  };

  for (const entry of zip.entries) {
    const name = entry.path;
    if (SKIP.test(name)) continue;
    if (SENSITIVE.test(name)) {
      skippedSensitive++;
      notHashed.push({ path: name, reason: "arquivo sensível: não lido por política" });
      continue;
    }
    paths.push(name);

    if (entry.declaredSize > zip.limits.maxEntryBytes) {
      notHashed.push({ path: name, reason: `maior que ${zip.limits.maxEntryBytes} bytes` });
      continue;
    }
    // Lê todos os arquivos não sensíveis para registrar a integridade (SHA-256), sempre pelo leitor seguro.
    const bytes = await zip.readBytes(entry);
    const fileSha256 = sha256Hex(bytes);
    hashes.push({ path: name, sha256: fileSha256, bytes: bytes.byteLength });

    const isText = TEXT.test(name) || DOCKERFILE.test(name);
    if (!isText || bytes.byteLength > MAX_TEXT || bytes.includes(0)) continue;
    const content = new TextDecoder().decode(bytes);
    textFiles++;

    if (/(^|\/)package\.json$/i.test(name)) {
      try { pkg ||= JSON.parse(content); } catch {
        add({ id: "CHL-PKG-INVALID", severity: "low", confidence: "high", title: "package.json inválido", evidence: "Manifesto JSON não pôde ser interpretado.", recommendation: "Corrija o JSON e repita a análise.", category: "Dependências", cwe: null }, name, null, fileSha256);
      }
    }
    if (/requirements\.txt$|pyproject\.toml$/i.test(name)) inventory.python.push(name);
    if (DOCKERFILE.test(name) || /docker-compose\.ya?ml$|compose\.ya?ml$/i.test(name)) inventory.docker.push(name);
    if (/\.ya?ml$/i.test(name) && /(kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob|Role|ClusterRole)|apiVersion:\s*.*\/)/i.test(content)) inventory.kubernetes.push(name);
    if (/\.tf$/i.test(name)) inventory.terraform.push(name);
    if (/(^|\/)vercel\.json$/i.test(name)) inventory.vercel = true;

    const lines = content.split(/\r?\n/);
    const perRule = new Map<string, number>();
    for (let i = 0; i < lines.length; i++) {
      const groupsHit = new Set<string>();
      for (const rule of LINE_RULES) {
        if (rule.group && groupsHit.has(rule.group)) continue;
        if (!rule.re.test(lines[i])) continue;
        if (rule.group) groupsHit.add(rule.group);
        const count = (perRule.get(rule.id) || 0) + 1;
        perRule.set(rule.id, count);
        if (count <= MAX_FINDINGS_PER_RULE_AND_FILE) add(rule, name, i + 1, fileSha256);
      }
    }

    if (DOCKERFILE.test(name)) {
      const rootUser = /^\s*USER\s+(root|0)\b/im;
      if (rootUser.test(content)) add({ id: "CHL-DOCKER-ROOT", severity: "medium", confidence: "high", title: "Container executa como root", evidence: "Dockerfile define USER root.", recommendation: "Crie usuário sem privilégios e use USER no estágio final.", category: "Container", cwe: "CWE-250" }, name, lineOf(content, rootUser), fileSha256);
      else if (!/^\s*USER\s+\S+/im.test(content)) add({ id: "CHL-DOCKER-NOUSER", severity: "medium", confidence: "medium", title: "Container pode executar como root", evidence: "Dockerfile não declara USER; a imagem base decide o usuário.", recommendation: "Crie usuário sem privilégios e use USER no estágio final.", category: "Container", cwe: "CWE-250" }, name, null, fileSha256);
      const latest = /^\s*FROM\s+\S+:latest(\s|$)/im;
      if (latest.test(content)) add({ id: "CHL-DOCKER-LATEST", severity: "low", confidence: "high", title: "Imagem Docker usa latest", evidence: "Tag latest reduz reprodutibilidade.", recommendation: "Fixe versão ou digest e atualize de forma controlada.", category: "Supply chain", cwe: null }, name, lineOf(content, latest), fileSha256);
    }
    if (/docker-compose\.ya?ml$|(^|\/)compose\.ya?ml$/i.test(name)) {
      const privileged = /privileged\s*:\s*true/i;
      if (privileged.test(content)) add({ id: "CHL-COMPOSE-PRIVILEGED", severity: "high", confidence: "high", title: "Container privilegiado", evidence: "privileged: true detectado.", recommendation: "Remova privileged e limite capabilities.", category: "Container", cwe: "CWE-250" }, name, lineOf(content, privileged), fileSha256);
      const bindAll = /["']?0\.0\.0\.0:\s*\d+/i;
      if (bindAll.test(content)) add({ id: "CHL-COMPOSE-BINDALL", severity: "low", confidence: "medium", title: "Porta publicada em todas as interfaces", evidence: "Binding 0.0.0.0 detectado.", recommendation: "Confirme necessidade e aplique firewall/autenticação.", category: "Rede", cwe: null }, name, lineOf(content, bindAll), fileSha256);
    }
    if (/\.ya?ml$/i.test(name) && /kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Job|CronJob)/i.test(content)) {
      const k8s: Array<[RegExp, Omit<LineRule, "re" | "group">]> = [
        [/privileged\s*:\s*true/i, { id: "CHL-K8S-PRIVILEGED", severity: "critical", confidence: "high", title: "Pod Kubernetes privilegiado", evidence: "securityContext contém privileged: true.", recommendation: "Remova modo privilegiado e aplique Pod Security Standards.", category: "Kubernetes", cwe: "CWE-250" }],
        [/host(?:Network|PID|IPC)\s*:\s*true/i, { id: "CHL-K8S-HOSTNS", severity: "high", confidence: "high", title: "Namespace do host compartilhado", evidence: "hostNetwork/hostPID/hostIPC habilitado.", recommendation: "Desative salvo necessidade documentada.", category: "Kubernetes", cwe: null }],
        [/hostPath\s*:/i, { id: "CHL-K8S-HOSTPATH", severity: "high", confidence: "high", title: "Volume hostPath detectado", evidence: "Manifesto monta caminho do host.", recommendation: "Prefira PVC e restrinja caminhos/permissões.", category: "Kubernetes", cwe: null }],
        [/runAsUser\s*:\s*0\b/i, { id: "CHL-K8S-UID0", severity: "high", confidence: "high", title: "Container Kubernetes como UID 0", evidence: "runAsUser: 0 detectado.", recommendation: "Use UID não privilegiado e runAsNonRoot: true.", category: "Kubernetes", cwe: "CWE-250" }],
        [/automountServiceAccountToken\s*:\s*true/i, { id: "CHL-K8S-SATOKEN", severity: "medium", confidence: "high", title: "Token ServiceAccount montado", evidence: "automountServiceAccountToken: true.", recommendation: "Desative quando a aplicação não acessar a API Kubernetes.", category: "Kubernetes", cwe: null }],
      ];
      for (const [re, rule] of k8s) if (re.test(content)) add(rule, name, lineOf(content, re), fileSha256);
    }
    if (/\.tf$/i.test(name)) {
      if (/0\.0\.0\.0\/0/.test(content) && /\b(22|3389)\b/.test(content)) add({ id: "CHL-TF-ADMINPORT", severity: "high", confidence: "low", title: "Possível exposição de SSH/RDP", evidence: "0.0.0.0/0 e porta administrativa aparecem no mesmo arquivo; a relação entre eles não foi verificada.", recommendation: "Restrinja CIDRs e prefira acesso privado/bastion.", category: "Terraform", cwe: null }, name, lineOf(content, /0\.0\.0\.0\/0/), fileSha256);
      const publicDb = /publicly_accessible\s*=\s*true/i;
      if (publicDb.test(content)) add({ id: "CHL-TF-PUBLICDB", severity: "high", confidence: "high", title: "Banco publicamente acessível", evidence: "publicly_accessible = true.", recommendation: "Desative acesso público e use sub-redes privadas.", category: "Terraform", cwe: null }, name, lineOf(content, publicDb), fileSha256);
      const publicAcl = /acl\s*=\s*["']public-read(?:-write)?["']/i;
      if (publicAcl.test(content)) add({ id: "CHL-TF-PUBLICACL", severity: "high", confidence: "high", title: "ACL pública em armazenamento", evidence: "public-read detectado.", recommendation: "Bloqueie acesso público por padrão.", category: "Terraform", cwe: null }, name, lineOf(content, publicAcl), fileSha256);
    }
  }

  Object.assign(deps, { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) });
  const depNames = Object.keys(deps);
  const unpinned = depNames.filter((n) => /^(latest|\*|x|https?:|git\+|git:|github:|file:)/i.test(String(deps[n]).trim()));
  if (unpinned.length) add({ id: "CHL-DEPS-UNPINNED", severity: "medium", confidence: "high", title: "Dependências sem versão fixa", evidence: "", recommendation: "Fixe versões e revise lockfile/alertas de supply chain.", category: "Supply chain", cwe: null }, "package.json", null, hashes.find((h) => /(^|\/)package\.json$/i.test(h.path))?.sha256 || null, `${unpinned.length} dependências mutáveis: ${unpinned.slice(0, 10).join(", ")}.`);
  if (inventory.kubernetes.length) add({ id: "CHL-INV-K8S", severity: "info", confidence: "high", title: "Manifestos Kubernetes identificados", evidence: "", recommendation: "Revise RBAC, NetworkPolicy, probes, recursos e políticas de admissão.", category: "Kubernetes", cwe: null }, inventory.kubernetes[0], null, null, `${inventory.kubernetes.length} manifesto(s) encontrados.`);
  if (inventory.terraform.length) add({ id: "CHL-INV-TF", severity: "info", confidence: "high", title: "Terraform identificado", evidence: "", recommendation: "Amplie com Checkov ou Trivy em ambiente controlado.", category: "IaC", cwe: null }, inventory.terraform[0], null, null, `${inventory.terraform.length} arquivo(s) encontrados.`);
  if (inventory.vercel) add({ id: "CHL-INV-VERCEL", severity: "info", confidence: "high", title: "Configuração Vercel identificada", evidence: "Configuração Vercel incluída no ZIP.", recommendation: "Revise rewrites, headers, funções e variáveis no painel Vercel.", category: "Cloud", cwe: null }, "vercel.json", null, null);

  return buildReport({ fileName, analyzedAt, zip, paths, textFiles, skippedSensitive, deps, depNames, inventory, findings, hashes, notHashed, framework: detectFramework(paths, pkg) });
}

function buildReport(input: {
  fileName: string; analyzedAt: string; zip: SafeZip; paths: string[]; textFiles: number; skippedSensitive: number;
  deps: Record<string, string>; depNames: string[]; inventory: { kubernetes: string[]; docker: string[]; terraform: string[]; python: string[]; vercel: boolean };
  findings: Finding[]; hashes: { path: string; sha256: string; bytes: number }[]; notHashed: { path: string; reason: string }[]; framework: string;
}) {
  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const confidenceCounts: Record<Confidence, number> = { high: 0, medium: 0, low: 0 };
  const statusCounts = Object.fromEntries(FINDING_STATUSES.map((s) => [s, 0])) as Record<FindingStatus, number>;
  for (const f of input.findings) { severityCounts[f.severity]++; confidenceCounts[f.confidence]++; statusCounts[f.status]++; }
  return {
    ok: true as const,
    schema: REPORT_SCHEMA,
    tool: { name: "CyberHuntLab", component: "ZIP static analyzer", version: ANALYZER_VERSION },
    fileName: input.fileName,
    framework: input.framework,
    analyzedAt: input.analyzedAt,
    integrity: {
      algorithm: "SHA-256" as const,
      archiveSha256: input.zip.archiveSha256,
      archiveBytes: input.zip.archiveBytes,
      bytesDecompressed: input.zip.bytesRead,
      files: input.hashes,
      notHashed: input.notHashed,
    },
    summary: {
      files: input.paths.length,
      textFiles: input.textFiles,
      skippedSensitive: input.skippedSensitive,
      dependencies: input.depNames.length,
      findings: input.findings.length,
      severityCounts,
      confidenceCounts,
      statusCounts,
    },
    inventory: { ...input.inventory, dependencies: input.depNames.slice(0, 100).map((name) => ({ name, version: input.deps[name] })) },
    findings: input.findings,
    limitations: [
      "Análise estática somente dos arquivos presentes no ZIP; não executa o projeto nem testa endpoints.",
      "Todos os achados são automatizados e começam como DETECTED. Nenhum achado é considerado vulnerabilidade confirmada sem validação de um pesquisador.",
      "Confiança indica a precisão da regra, não a gravidade: regras de confiança baixa são heurísticas e exigem leitura do contexto.",
      "Não há análise de fluxo de dados (taint) nesta versão: execução dinâmica e segredos genéricos não são correlacionados com entradas do usuário.",
      "Não consulta automaticamente bases CVE/OSV; versões são inventariadas, não declaradas vulneráveis.",
      "Não acessa sua conta Vercel nem um cluster Kubernetes remoto; analisa somente configurações incluídas no ZIP.",
    ],
  };
}
