/**
 * CyberHuntLab — modelo de achados e estados de validação.
 * Módulo puro (sem Node nem Next): usado pelo analisador no servidor e pela interface no navegador.
 *
 * Fluxo: DETECTED → ANALYZING → EVIDENCE_FOUND → VALIDATED | UNCONFIRMED | FALSE_POSITIVE
 * O analisador só cria DETECTED. Os demais estados são decisões registradas do pesquisador.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export const FINDING_STATUSES = ["DETECTED", "ANALYZING", "EVIDENCE_FOUND", "VALIDATED", "UNCONFIRMED", "FALSE_POSITIVE"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export type StatusChange = { status: FindingStatus; at: string; by: "analyzer" | "researcher"; note?: string };

export type Finding = {
  id: string;
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  origin: "automated";
  title: string;
  file: string;
  line: number | null;
  fileSha256: string | null;
  evidence: string;
  recommendation: string;
  category: string;
  cwe: string | null;
  history: StatusChange[];
};

export const STATUS_LABELS: Record<FindingStatus, string> = {
  DETECTED: "Detectado (automático)",
  ANALYZING: "Em análise",
  EVIDENCE_FOUND: "Evidência encontrada",
  VALIDATED: "Validado pelo pesquisador",
  UNCONFIRMED: "Não confirmado",
  FALSE_POSITIVE: "Falso positivo",
};

export const CONFIDENCE_LABELS: Record<Confidence, string> = { high: "Alta", medium: "Média", low: "Baixa" };

/** Aplica uma mudança de estado feita pelo pesquisador, preservando o histórico completo. */
export function applyStatusChange(finding: Finding, status: FindingStatus, note?: string, at = new Date()): Finding {
  if (!(FINDING_STATUSES as readonly string[]).includes(status)) throw new Error(`Estado inválido: ${status}`);
  if (status === "DETECTED") throw new Error("DETECTED é reservado ao analisador automático.");
  const cleanNote = note?.trim().slice(0, 1000) || undefined;
  return { ...finding, status, history: [...finding.history, { status, at: at.toISOString(), by: "researcher", note: cleanNote }] };
}
