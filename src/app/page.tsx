"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { applyStatusChange, CONFIDENCE_LABELS, FINDING_STATUSES, STATUS_LABELS, type FindingStatus } from "@/lib/audit/findings";
import {
  ArrowUp,
  Paperclip,
  Plus,
  Settings2,
  MessageSquare,
  Code2,
  FolderOpen,
  X,
  Square,
  Check,
  AlertCircle,
  Menu,
  Copy,
  Github,
  Puzzle,
  UploadCloud,
  RefreshCw,
  Trash2,
  ExternalLink,
  Key,
  Eye,
  EyeOff,
  LogOut,
  CheckCircle2,
  Sparkles,
  Zap,
  ShieldCheck,
  Layers,
  FileCode,
  Sliders,
  ChevronRight,
  Terminal,
  Instagram,
  Search,
  Cpu,
  PlugZap,
  Database,
  CircleDollarSign,
} from "lucide-react";

type Chat = { id: string; title: string; updatedAt: number };
type Msg = { id: string; role: "user" | "assistant"; text: string; time: number; status?: string; artifact?: { id: string; fileName: string; fileCount: number } };
type PendingTask = { chatId: string; text: string; files: File[] };
type Skill = { id: string; name: string; description: string; category?: string; tags?: string[]; version?: string };
type GitHubUser = {
  login: string;
  name: string;
  avatar_url: string;
  html_url: string;
  public_repos?: number;
};

type ProviderModel = { id: string; name: string; context: number | null; output: number | null; inputPrice: number | null; outputPrice: number | null; free: boolean; modalities?: any };
type ProviderInfo = { id: string; name: string; connected: boolean; authMethods?: { type: string; label?: string }[]; models: ProviderModel[] };

type ApiKeysState = {
  groq: string;
  openai: string;
  anthropic: string;
  gemini: string;
  customServerUrl: string;
  customServerPassword: string;
};

type CredentialStatus = {
  groq: boolean;
  openai: boolean;
  anthropic: boolean;
  gemini: boolean;
  github: { connected: boolean; user: GitHubUser | null };
  opencode: { url: string; hasPassword: boolean } | null;
};

const EMPTY_CREDENTIALS: CredentialStatus = { groq: false, openai: false, anthropic: false, gemini: false, github: { connected: false, user: null }, opencode: null };

type ReverseEngResult = {
  fileName: string;
  fileSize: number;
  totalFiles: number;
  detectedFramework: string;
  dependencies: Record<string, string>;
  componentsCount: number;
  routesCount: number;
  structureTree: string[];
};

const STORE = "opencode-workspace-v4";
// Chaves legadas (≤ v1.0) que guardavam segredos no localStorage. Na v1.1 elas são migradas uma
// única vez para o cofre cifrado do servidor e apagadas do navegador.
const LEGACY_GITHUB_TOKEN = "opencode-github-token";
const LEGACY_GITHUB_USER = "opencode-github-user";
const LEGACY_API_KEYS = "opencode-user-api-keys";

// Modelos Groq de produção; o fallback consulta a lista ativa da própria Groq.
const MODELS = [
  { id: "groq/openai/gpt-oss-120b", label: "GPT-OSS 120B (Groq · Raciocínio e código)", group: "Groq" },
  { id: "groq/openai/gpt-oss-20b", label: "GPT-OSS 20B (Groq · Rápido)", group: "Groq" },
  { id: "groq/qwen/qwen3.8-27b", label: "Qwen 3.8 27B (Groq · Raciocínio)", group: "Groq" },
  { id: "groq/minimaxai/minimax-m2.7", label: "MiniMax M2.7 (Groq)", group: "Groq" },
];

const SKILL_CATEGORIES = [
  "Todas",
  "Engenharia Reversa",
  "IA & Modelos Groq",
  "Frontend & UI",
  "Backend & APIs",
  "Segurança & Auth",
  "Bancos de Dados",
  "DevOps & CI/CD",
  "Arquitetura & Clean Code",
];

function Workbench({ onLogout }: { onLogout: () => void }) {
  const [hydrated, setHydrated] = useState(false);
  const [tab, setTab] = useState<"chat" | "reverse" | "security" | "skills" | "apresentacao">("chat");
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Chats
  const [chats, setChats] = useState<Chat[]>([]);
  const [active, setActive] = useState("");
  const [messages, setMessages] = useState<Record<string, Msg[]>>({});
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [queuedCount, setQueuedCount] = useState(0);
  const [model, setModel] = useState("groq/openai/gpt-oss-120b");
  const [files, setFiles] = useState<File[]>([]);
  const [status, setStatus] = useState("Pronto para trabalhar");
  const [serverReady, setServerReady] = useState<boolean | null>(null);
  const [sessionMap, setSessionMap] = useState<Record<string, string>>({});

  // 20k Skills state with Progressive Disclosure
  const [skills, setSkills] = useState<Skill[]>([]);
  const [skillsTotal, setSkillsTotal] = useState(0);
  const [skillQuery, setSkillQuery] = useState("");
  const [skillCategory, setSkillCategory] = useState("Todas");
  const [skillsPage, setSkillsPage] = useState(1);
  const [selectedSkillDetail, setSelectedSkillDetail] = useState<any>(null);
  const [loadingSkillDetail, setLoadingSkillDetail] = useState(false);

  // Reverse Engineering & ZIP State
  const [zip, setZip] = useState<File | null>(null);
  const [zipValidation, setZipValidation] = useState<{ valid: boolean; message: string; filesCount?: number } | null>(null);
  const [reverseBusy, setReverseBusy] = useState(false);
  const [reverseResult, setReverseResult] = useState<ReverseEngResult | null>(null);
  const [securityBusy, setSecurityBusy] = useState(false);
  const [securityReport, setSecurityReport] = useState<any>(null);
  const [findingNotes, setFindingNotes] = useState<Record<string, string>>({});

  // GitHub Publish State
  const [repo, setRepo] = useState("");
  const [branch, setBranch] = useState("main");
  const [githubBusy, setGithubBusy] = useState(false);
  const [publishNotice, setPublishNotice] = useState("");

  // GitHub Auth
  const [githubAuthModal, setGithubAuthModal] = useState(false);
  // O token do GitHub fica somente no cofre do servidor; o navegador conhece apenas o perfil público.
  const [credStatus, setCredStatus] = useState<CredentialStatus>(EMPTY_CREDENTIALS);
  const githubUser = credStatus.github.user;
  const [tokenInput, setTokenInput] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [verifyingToken, setVerifyingToken] = useState(false);
  const [authFeedback, setAuthFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Custom User APIs (BYOK)
  const [apiModal, setApiModal] = useState(false);
  const [apiKeys, setApiKeys] = useState<ApiKeysState>({
    groq: "",
    openai: "",
    anthropic: "",
    gemini: "",
    customServerUrl: "",
    customServerPassword: "",
  });
  const [apiSavedNotice, setApiSavedNotice] = useState(false);
  const [apiSaveError, setApiSaveError] = useState("");

  // Settings
  const [settings, setSettings] = useState(false);
  const [providerCatalog, setProviderCatalog] = useState<ProviderInfo[]>([]);
  const [providerSearch, setProviderSearch] = useState("");
  const [providerLoading, setProviderLoading] = useState(false);
  const [providerError, setProviderError] = useState("");
  const [activeProvider, setActiveProvider] = useState("");
  const [providerApiKey, setProviderApiKey] = useState("");
  const [providerSaving, setProviderSaving] = useState(false);
  const [providerFeedback, setProviderFeedback] = useState("");
  const [routerStatus, setRouterStatus] = useState<"not-configured" | "offline" | "ready">("not-configured");
  const [routerBusy, setRouterBusy] = useState(false);
  const [routerFeedback, setRouterFeedback] = useState("");
  const [routerDefaultModel, setRouterDefaultModel] = useState("");

  const endRef = useRef<HTMLDivElement>(null);
  const busyRef = useRef(false);
  const taskQueueRef = useRef<PendingTask[]>([]);
  const workspaceByChatRef = useRef<Record<string, { base64: string; fileName: string }>>({});
  const artifactByIdRef = useRef<Record<string, string>>({});
  const fileRef = useRef<HTMLInputElement>(null);
  const zipInputRef = useRef<HTMLInputElement>(null);

  const current = messages[active] || [];

  const loadProviderCatalog = async () => {
    setProviderLoading(true);
    setProviderError("");
    try {
      const response = await fetch("/api/models", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        cache: "no-store",
        body: "{}",
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || data.hint || "Não foi possível carregar os modelos.");
      setProviderCatalog(data.providers || []);
      setRouterStatus(data.router?.connected ? "ready" : data.router?.configured ? "offline" : "not-configured");
      setRouterDefaultModel(data.router?.defaultModel || "");
      if (data.router?.error) setRouterFeedback(data.router.error);
      setActiveProvider((current) => current || data.providers?.find((p: ProviderInfo) => p.connected)?.id || data.providers?.[0]?.id || "");
    } catch (error) {
      setProviderError(error instanceof Error ? error.message : "Falha ao consultar o catálogo OpenCode.");
    } finally {
      setProviderLoading(false);
    }
  };

  const startNineRouter = async () => {
    setRouterBusy(true);
    setRouterFeedback("");
    try {
      const response = await fetch("/api/9router/start", { method: "POST", cache: "no-store" });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || "Não foi possível conectar ao 9Router.");
      setRouterStatus("ready");
      setRouterDefaultModel(data.defaultModel);
      setModel(`9router/${data.defaultModel}`);
      setRouterFeedback(`Ativo · ${data.modelCount} modelos sincronizados · combo ${data.defaultModel} selecionado.`);
      await loadProviderCatalog();
    } catch (error) {
      setRouterStatus("offline");
      setRouterFeedback(error instanceof Error ? error.message : "Falha ao iniciar 9Router.");
    } finally {
      setRouterBusy(false);
    }
  };

  const syncNineRouter = async () => {
    setRouterBusy(true);
    setRouterFeedback("");
    try {
      const response = await fetch("/api/9router/models", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok || !data.connected) throw new Error(data.error || data.message || "9Router não está disponível.");
      setRouterStatus("ready");
      setRouterFeedback(`${data.models.length} modelos sincronizados com o 9Router.`);
      await loadProviderCatalog();
    } catch (error) {
      setRouterStatus("offline");
      setRouterFeedback(error instanceof Error ? error.message : "Falha ao sincronizar catálogo.");
    } finally {
      setRouterBusy(false);
    }
  };

  const connectProvider = async () => {
    if (!activeProvider || !providerApiKey.trim()) return;
    setProviderSaving(true);
    setProviderFeedback("");
    try {
      const response = await fetch(`/api/providers/${encodeURIComponent(activeProvider)}/auth`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: providerApiKey.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Não foi possível conectar o provedor.");
      setProviderApiKey("");
      setProviderFeedback(`Conectado: ${activeProvider}. Atualizando modelos...`);
      await loadProviderCatalog();
    } catch (error) {
      setProviderFeedback(error instanceof Error ? error.message : "Falha ao conectar.");
    } finally {
      setProviderSaving(false);
    }
  };

  const visibleProviders = providerCatalog.filter((provider) => {
    const query = providerSearch.trim().toLowerCase();
    return !query || provider.name.toLowerCase().includes(query) || provider.id.toLowerCase().includes(query) || provider.models.some((item) => item.name.toLowerCase().includes(query) || item.id.toLowerCase().includes(query));
  });
  const selectedProviderInfo = providerCatalog.find((provider) => provider.id === activeProvider);
  const selectedProviderHasApiKey = selectedProviderInfo?.authMethods?.some((method) => method.type === "api") ?? true;
  const selectedProviderHasOAuth = selectedProviderInfo?.authMethods?.some((method) => method.type === "oauth") ?? false;
  const visibleModels = (selectedProviderInfo?.models || []).filter((item) => {
    const query = providerSearch.trim().toLowerCase();
    return !query || item.name.toLowerCase().includes(query) || item.id.toLowerCase().includes(query);
  });

  useEffect(() => {
    if (hydrated) void loadProviderCatalog();
  }, [hydrated]);

  // Hydration
  useEffect(() => {
    try {
      const s = localStorage.getItem(STORE);
      if (s) {
        const d = JSON.parse(s);
        setChats(d.chats || []);
        setMessages(d.messages || {});
        setActive(d.active || d.chats?.[0]?.id || "");
        const oldModel = d.model || "";
        const retiredGroqModels = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "qwen-qwq-32b", "mixtral-8x7b-32768", "gemma2-9b-it"];
        setModel(retiredGroqModels.includes(oldModel) ? "groq/openai/gpt-oss-120b" : (oldModel || "groq/openai/gpt-oss-120b"));
        setSessionMap(d.sessionMap || {});
        if (d.tab) setTab(d.tab);
      }
      try {
        const cachedWorkspaceRaw = sessionStorage.getItem("openui-code-code-workspace");
        if (cachedWorkspaceRaw) {
          const cachedWorkspace = JSON.parse(cachedWorkspaceRaw);
          if (cachedWorkspace?.chatId && cachedWorkspace?.base64 && cachedWorkspace?.fileName) {
            workspaceByChatRef.current[cachedWorkspace.chatId] = { base64: cachedWorkspace.base64, fileName: cachedWorkspace.fileName };
            if (cachedWorkspace.artifactId) artifactByIdRef.current[cachedWorkspace.artifactId] = cachedWorkspace.base64;
            const binary = atob(cachedWorkspace.base64);
            const bytes = new Uint8Array(binary.length);
            for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
            setZip(new File([bytes.buffer as ArrayBuffer], cachedWorkspace.fileName, { type: "application/zip" }));
            setZipValidation({ valid: true, message: `Projeto recuperado da sessão: ${cachedWorkspace.fileName}.` });
          }
        }
      } catch { /* cache opcional; não bloqueia a hidratação da interface */ }
    } catch {
      // Ignore
    } finally {
      setHydrated(true);
    }
  }, []);

  // Save State
  useEffect(() => {
    if (hydrated) {
      localStorage.setItem(
        STORE,
        JSON.stringify({ chats, messages, active, model, sessionMap, tab })
      );
    }
  }, [chats, messages, active, model, sessionMap, tab, hydrated]);

  async function refreshCredentials() {
    try {
      const response = await fetch("/api/credentials", { cache: "no-store" });
      const data = await response.json();
      if (response.ok && data.credentials) setCredStatus(data.credentials);
    } catch { /* status indisponível; as rotas continuam validando no servidor */ }
  }

  async function saveCredential(body: Record<string, unknown>): Promise<CredentialStatus> {
    const response = await fetch("/api/credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Não foi possível salvar a credencial.");
    setCredStatus(data.credentials);
    return data.credentials;
  }

  async function removeCredential(kind: string) {
    const response = await fetch(`/api/credentials?kind=${encodeURIComponent(kind)}`, { method: "DELETE" });
    const data = await response.json();
    if (response.ok && data.credentials) setCredStatus(data.credentials);
  }

  // Carrega o status das credenciais e migra segredos legados do localStorage para o cofre do servidor.
  useEffect(() => {
    if (!hydrated) return;
    void (async () => {
      const notes: string[] = [];
      try {
        const legacyKeysRaw = localStorage.getItem(LEGACY_API_KEYS);
        const legacyGithub = localStorage.getItem(LEGACY_GITHUB_TOKEN);
        // Remove primeiro: o segredo não deve continuar no navegador mesmo se a migração falhar.
        localStorage.removeItem(LEGACY_API_KEYS);
        localStorage.removeItem(LEGACY_GITHUB_TOKEN);
        localStorage.removeItem(LEGACY_GITHUB_USER);
        const legacy = legacyKeysRaw ? JSON.parse(legacyKeysRaw) as Partial<ApiKeysState> : {};
        for (const kind of ["groq", "openai", "anthropic", "gemini"] as const) {
          const value = typeof legacy[kind] === "string" ? legacy[kind]!.trim() : "";
          if (value) await saveCredential({ kind, value }).catch((e) => notes.push(`${kind}: ${e instanceof Error ? e.message : "falhou"}`));
        }
        if (legacy.customServerUrl?.trim()) {
          await saveCredential({ kind: "opencode", url: legacy.customServerUrl.trim(), password: legacy.customServerPassword || "" })
            .catch((e) => notes.push(`OpenCode: ${e instanceof Error ? e.message : "falhou"}`));
        }
        if (legacyGithub?.trim()) await saveCredential({ kind: "github", value: legacyGithub.trim() }).catch((e) => notes.push(`GitHub: ${e instanceof Error ? e.message : "falhou"}`));
      } catch { /* dados legados ilegíveis: já foram removidos */ }
      await refreshCredentials();
      if (notes.length) setApiSaveError(`Algumas credenciais antigas não puderam ser migradas e precisam ser informadas novamente: ${notes.join(" · ")}`);
    })();
  }, [hydrated]);

  useEffect(() => {
    if (!active && chats.length) setActive(chats[0].id);
  }, [active, chats]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [current.length, busy]);

  // Load health & initial skills
  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => setServerReady(!!d.ok))
      .catch(() => setServerReady(false));
    loadSkills(1, skillQuery, skillCategory);
  }, []);

  // Load Skills with Progressive Disclosure
  async function loadSkills(page = 1, query = skillQuery, category = skillCategory) {
    try {
      const params = new URLSearchParams({
        page: String(page),
        limit: "24",
      });
      if (query.trim()) params.set("q", query.trim());
      if (category && category !== "Todas") params.set("category", category);

      const r = await fetch(`/api/skills?${params.toString()}`);
      const d = await r.json();
      setSkills(d.skills || []);
      setSkillsTotal(d.total || 0);
      setSkillsPage(d.page || 1);
    } catch {
      setSkills([]);
    }
  }

  // Progressive Disclosure: Load Level 2 Detail on demand
  async function inspectSkillDetail(skillId: string) {
    setLoadingSkillDetail(true);
    try {
      const res = await fetch(`/api/skills?detail=${encodeURIComponent(skillId)}`);
      const data = await res.json();
      if (data.skill) {
        setSelectedSkillDetail(data.skill);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingSkillDetail(false);
    }
  }

  function injectSkillIntoChat(promptSnippet: string) {
    setInput((prev) => (prev ? `${prev}\n\n${promptSnippet}` : promptSnippet));
    setTab("chat");
    setDrawerOpen(false);
    setSelectedSkillDetail(null);
  }

  function newChat() {
    const id = crypto.randomUUID();
    setChats((v) => [{ id, title: "Nova conversa", updatedAt: Date.now() }, ...v]);
    setMessages((v) => ({ ...v, [id]: [] }));
    setActive(id);
    setInput("");
    setFiles([]);
    setTab("chat");
    setDrawerOpen(false);
  }

  function deleteChat(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    setChats((v) => v.filter((c) => c.id !== id));
    setMessages((v) => {
      const copy = { ...v };
      delete copy[id];
      return copy;
    });
    if (active === id) {
      const remaining = chats.filter((c) => c.id !== id);
      setActive(remaining[0]?.id || "");
    }
  }

  function addMessage(id: string, m: Msg) {
    setMessages((v) => ({ ...v, [id]: [...(v[id] || []), m] }));
  }

  // Handle ZIP file selection & instant validation (Fixes UI bug where button stays disabled)
  async function handleZipSelection(selectedFile: File | null) {
    if (!selectedFile) {
      setZip(null);
      setZipValidation(null);
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".zip")) {
      setZip(null);
      setZipValidation({
        valid: false,
        message: "O arquivo selecionado não possui extensão .zip válida.",
      });
      return;
    }

    if (selectedFile.size > 3 * 1024 * 1024) {
      setZip(null);
      setZipValidation({
        valid: false,
        message: "O arquivo excede o limite de 3 MB desta implantação Vercel.",
      });
      return;
    }

    setZip(selectedFile);
    setZipValidation({
      valid: true,
      message: `Arquivo válido: ${selectedFile.name} (${(selectedFile.size / 1024 / 1024).toFixed(2)} MB)`,
    });
  }

  // Execute Clean-Room Reverse Engineering
  async function runReverseEngineering() {
    if (!zip) return;
    setReverseBusy(true);
    setReverseResult(null);
    try {
      const fd = new FormData();
      fd.append("archive", zip);
      const res = await fetch("/api/reverse-engineering", {
        method: "POST",
        body: fd,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Falha na análise de engenharia reversa.");
      setReverseResult(data);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Erro na engenharia reversa.");
    } finally {
      setReverseBusy(false);
    }
  }

  async function runSecurityAudit() {
    if (!zip) return;
    setSecurityBusy(true);
    setSecurityReport(null);
    try {
      const fd = new FormData();
      fd.append("archive", zip);
      const response = await fetch("/api/security-audit", { method: "POST", body: fd });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Falha na análise de segurança.");
      setSecurityReport(data);
    } catch (error) {
      alert(error instanceof Error ? error.message : "Erro na análise de segurança.");
    } finally {
      setSecurityBusy(false);
    }
  }

  // Decisão do pesquisador sobre um achado: altera o estado e registra no histórico (exportado no JSON).
  function updateFindingStatus(findingId: string, status: FindingStatus) {
    setSecurityReport((report: any) => {
      if (!report) return report;
      const findings = report.findings.map((finding: any) => finding.id === findingId ? applyStatusChange(finding, status, findingNotes[findingId]) : finding);
      const statusCounts = Object.fromEntries(FINDING_STATUSES.map((s) => [s, findings.filter((f: any) => f.status === s).length]));
      return { ...report, findings, summary: { ...report.summary, statusCounts } };
    });
    setFindingNotes((notes) => ({ ...notes, [findingId]: "" }));
  }

  function exportSecurityReport() {
    if (!securityReport) return;
    const exported = { ...securityReport, exportedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberhuntlab-report-${String(securityReport.integrity?.archiveSha256 || "zip").slice(0, 12)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function sendSecurityReportToAI() {
    if (!securityReport) return;
    const prompt = `Atue como analista sênior de AppSec/Cloud Security. Analise criticamente o relatório estático abaixo.

Regras: não invente vulnerabilidades, CVEs, versões afetadas, exploração ou testes executados. Respeite os campos "confidence" (precisão da regra) e "status" (DETECTED = automático, não validado; VALIDATED/FALSE_POSITIVE = decisão do pesquisador). Diferencie achado confirmado de suspeita, explique falsos positivos possíveis, priorize por risco e contexto, proponha correções verificáveis e testes seguros. O escopo é somente o ZIP fornecido e sistemas que o usuário tem autorização para avaliar.

RELATÓRIO JSON (lista de hashes por arquivo omitida; o hash do ZIP identifica a versão analisada):
${JSON.stringify({ ...securityReport, integrity: securityReport.integrity ? { archiveSha256: securityReport.integrity.archiveSha256, filesHashed: securityReport.integrity.files?.length ?? 0 } : undefined }, null, 2)}

Entregue: resumo executivo, achados priorizados, evidências, impacto potencial, validação manual segura, correções e limitações.`;
    let id = active;
    if (!id) {
      id = crypto.randomUUID();
      setChats((v) => [{ id, title: "Análise AppSec do ZIP", updatedAt: Date.now() }, ...v]);
      setMessages((v) => ({ ...v, [id]: [] }));
      setActive(id);
    }
    const task: PendingTask = { chatId: id, text: prompt, files: [] };
    addUserTaskMessage(task);
    setTab("chat");
    if (busyRef.current) {
      taskQueueRef.current.push(task);
      setQueuedCount(taskQueueRef.current.length);
    } else {
      void drainTaskQueue(task);
    }
  }

  // Send reverse engineering prompt directly to OpenCode / Groq Chat
  function sendReversePromptToChat() {
    if (!reverseResult || !zip) return;
    const text = "Faça uma recriação Clean-Room do ZIP anexado. Preserve a estrutura técnica e os arquivos necessários, atualize o README, implemente o projeto funcional com identidade visual original e entregue um novo ZIP completo. Trabalhe somente com conteúdo que tenho autorização para modificar.";
    let id = active;
    if (!id) {
      id = crypto.randomUUID();
      setChats((v) => [{ id, title: "Recriação do projeto", updatedAt: Date.now() }, ...v]);
      setMessages((v) => ({ ...v, [id]: [] }));
      setActive(id);
    }
    const task: PendingTask = { chatId: id, text, files: [zip] };
    addUserTaskMessage(task);
    setInput("");
    setFiles([]);
    setTab("chat");
    if (busyRef.current) {
      taskQueueRef.current.push(task);
      setQueuedCount(taskQueueRef.current.length);
    } else {
      void drainTaskQueue(task);
    }
  }

  function addUserTaskMessage(task: PendingTask) {
    const names = task.files.map((f) => f.name);
    const userText = task.text + (names.length ? `\n\nAnexos selecionados: ${names.join(", ")}` : "");
    addMessage(task.chatId, { id: crypto.randomUUID(), role: "user", text: userText, time: Date.now() });
    setChats((v) => v.map((c) => c.id === task.chatId
      ? { ...c, title: task.text.slice(0, 42) || names[0] || "Nova tarefa", updatedAt: Date.now() }
      : c));
  }

  function downloadWorkspaceZip(artifactId: string, fileName: string) {
    const base64 = artifactByIdRef.current[artifactId];
    if (!base64) {
      window.alert("Este arquivo não está mais disponível nesta sessão. Anexe novamente o ZIP anterior para continuar.");
      return;
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const blob = new Blob([bytes.buffer as ArrayBuffer], { type: "application/zip" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function executeTask(task: PendingTask) {
    const zipAttachment = task.files.find((f) => f.name.toLowerCase().endsWith(".zip"));
    const previousWorkspace = workspaceByChatRef.current[task.chatId];
    const projectIntent = /\b(crie|criar|desenvolva|desenvolver|construa|construir|implemente|implementar|atualize|atualizar|modifique|modificar|corrija|corrigir|refatore|refatorar|adicione|adicionar|remova|remover|gere|gerar|exporte|empacote|projeto|aplicativo|aplicação|site|sistema|pasta|arquivos|código|codigo|zip|engenharia reversa)\b/i.test(task.text);
    const workspaceMode = Boolean(zipAttachment || previousWorkspace || projectIntent);

    try {
      if (workspaceMode) {
        setStatus(previousWorkspace || zipAttachment ? "Lendo estrutura e preparando alterações..." : "Construindo projeto e preparando arquivos...");
        const form = new FormData();
        form.append("prompt", task.text || "Analise e organize o projeto anexado.");
        form.append("model", model);
        if (zipAttachment) form.append("archive", zipAttachment);
        else if (previousWorkspace) form.append("archiveBase64", previousWorkspace.base64);

        const response = await fetch("/api/workspace", { method: "POST", body: form });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Não foi possível gerar o projeto.");
        workspaceByChatRef.current[task.chatId] = { base64: data.zipBase64, fileName: data.fileName };
        const artifactId = crypto.randomUUID();
        artifactByIdRef.current[artifactId] = data.zipBase64;
        try {
          sessionStorage.setItem("openui-code-code-workspace", JSON.stringify({ chatId: task.chatId, base64: data.zipBase64, fileName: data.fileName, artifactId }));
        } catch { /* o ZIP continua disponível em memória nesta sessão */ }
        const zipBinary = atob(data.zipBase64);
        const zipBytes = new Uint8Array(zipBinary.length);
        for (let index = 0; index < zipBinary.length; index++) zipBytes[index] = zipBinary.charCodeAt(index);
        const generatedZip = new File([zipBytes.buffer as ArrayBuffer], data.fileName, { type: "application/zip" });
        setZip(generatedZip);
        setZipValidation({ valid: true, message: `Projeto gerado: ${data.fileName} (${data.fileCount} arquivos). Pronto para publicação no GitHub.` });
        const checks = Array.isArray(data.checks) && data.checks.length
          ? `\n\nVerificações: ${data.checks.join(" · ")}`
          : "";
        addMessage(task.chatId, {
          id: crypto.randomUUID(),
          role: "assistant",
          text: `${data.summary || "Projeto empacotado."}\n\n${data.fileCount} arquivos incluídos no ZIP.${checks}\n\nO ZIP está pronto para baixar e também foi disponibilizado para a ferramenta de publicação no GitHub. Para solicitar novas alterações, continue nesta conversa.`,
          time: Date.now(),
          artifact: { id: artifactId, fileName: data.fileName, fileCount: data.fileCount },
        });
        setStatus("ZIP pronto para entrega");
      } else {
        const names = task.files.map((f) => f.name);
        const response = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            sessionId: sessionMap[task.chatId] || "",
            clientChatId: task.chatId,
            message: task.text || `Analise os arquivos anexados: ${names.join(", ")}`,
            model,
          }),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Falha na execução");
        if (data.sessionId) setSessionMap((v) => ({ ...v, [task.chatId]: data.sessionId }));
        addMessage(task.chatId, { id: crypto.randomUUID(), role: "assistant", text: data.message || "Instrução concluída.", time: Date.now() });
        setStatus("Concluído");
      }
    } catch (error) {
      addMessage(task.chatId, {
        id: crypto.randomUUID(),
        role: "assistant",
        text: `Não foi possível concluir a tarefa: ${error instanceof Error ? error.message : "Erro desconhecido"}`,
        time: Date.now(),
        status: "error",
      });
      setStatus("Falha na execução");
    }
  }

  async function drainTaskQueue(firstTask: PendingTask) {
    if (busyRef.current) {
      taskQueueRef.current.push(firstTask);
      setQueuedCount(taskQueueRef.current.length);
      return;
    }
    busyRef.current = true;
    setBusy(true);
    let task: PendingTask | undefined = firstTask;
    try {
      while (task) {
        await executeTask(task);
        task = taskQueueRef.current.shift();
        setQueuedCount(taskQueueRef.current.length);
      }
    } finally {
      busyRef.current = false;
      setBusy(false);
      setQueuedCount(0);
      setStatus("Pronto para trabalhar");
    }
  }

  // Novas mensagens entram na fila; nunca interrompem o trabalho em andamento.
  function send() {
    const text = input.trim();
    if (!text && !files.length) return;
    let id = active;
    if (!id) {
      id = crypto.randomUUID();
      setChats((v) => [{ id, title: text.slice(0, 42) || "Nova conversa", updatedAt: Date.now() }, ...v]);
      setMessages((v) => ({ ...v, [id]: [] }));
      setActive(id);
    }
    const task: PendingTask = { chatId: id, text, files: [...files] };
    addUserTaskMessage(task);
    setInput("");
    setFiles([]);
    if (busyRef.current) {
      taskQueueRef.current.push(task);
      setQueuedCount(taskQueueRef.current.length);
      setStatus("Sua próxima instrução foi adicionada à fila.");
      return;
    }
    void drainTaskQueue(task);
  }

  // GitHub Auth
  async function connectGitHubToken() {
    if (!tokenInput.trim()) {
      setAuthFeedback({ type: "error", text: "Cole sua frase de token do GitHub." });
      return;
    }
    setVerifyingToken(true);
    setAuthFeedback(null);
    try {
      const status = await saveCredential({ kind: "github", value: tokenInput.trim() });
      setTokenInput("");
      setAuthFeedback({
        type: "success",
        text: `Conectado com sucesso como @${status.github.user?.login || "GitHub"}! O token ficou cifrado no servidor.`,
      });
      setTimeout(() => setGithubAuthModal(false), 1200);
    } catch (err) {
      setAuthFeedback({
        type: "error",
        text: err instanceof Error ? err.message : "Erro desconhecido ao conectar.",
      });
    } finally {
      setVerifyingToken(false);
    }
  }

  function disconnectGitHub() {
    void removeCredential("github");
    setTokenInput("");
    setAuthFeedback(null);
  }

  async function saveCustomApiKeys() {
    setApiSaveError("");
    setApiSavedNotice(false);
    try {
      // Cada chave é enviada uma vez ao servidor, validada (Groq) e cifrada no cofre HttpOnly.
      for (const kind of ["groq", "openai", "anthropic", "gemini"] as const) {
        const value = apiKeys[kind].trim();
        if (value) await saveCredential({ kind, value });
      }
      if (apiKeys.customServerUrl.trim()) {
        await saveCredential({ kind: "opencode", url: apiKeys.customServerUrl.trim(), password: apiKeys.customServerPassword });
      }
    } catch (error) {
      setApiSaveError(error instanceof Error ? error.message : "Não foi possível salvar a credencial.");
      return;
    }
    // Os campos são limpos: o navegador não mantém cópia das chaves.
    setApiKeys({ groq: "", openai: "", anthropic: "", gemini: "", customServerUrl: "", customServerPassword: "" });
    void loadProviderCatalog();
    setApiSavedNotice(true);
    setTimeout(() => setApiSavedNotice(false), 3500);
  }

  // Publish to GitHub via Git Trees API
  async function publishZip() {
    if (!zip || !repo.trim()) {
      setPublishNotice("Selecione um arquivo ZIP e informe o repositório no formato owner/nome.");
      return;
    }
    setGithubBusy(true);
    setPublishNotice("Descompactando e criando árvore no GitHub...");
    try {
      const fd = new FormData();
      fd.append("archive", zip);
      fd.append("repository", repo.trim());
      fd.append("branch", branch.trim());
      fd.append("notifyOpenCode", "true");
      // O token é lido do cofre do servidor; o navegador não o envia.
      const r = await fetch("/api/github/publish", { method: "POST", body: fd });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Falha ao publicar");
      setPublishNotice(d.message || "Publicação concluída com sucesso via Git Trees API.");
    } catch (e) {
      setPublishNotice(e instanceof Error ? e.message : "Erro ao publicar no GitHub.");
    } finally {
      setGithubBusy(false);
    }
  }

  const sorted = useMemo(() => [...chats].sort((a, b) => b.updatedAt - a.updatedAt), [chats]);

  const configuredKeysCount = [
    credStatus.groq,
    credStatus.openai,
    credStatus.anthropic,
    credStatus.gemini,
    credStatus.github.connected,
    Boolean(credStatus.opencode),
  ].filter(Boolean).length;

  return (
    <main className="shell">
      {/* ============================================================
          TOPBAR (CLEAN, MINIMAL & STRICTLY RESPONSIVE)
          - Desktop: "OpenCode" title, tabs and primary actions.
          - Mobile (<=768px): ONLY hamburger (☰) and "OpenCode".
          ============================================================ */}
      <header className="topbar">
        <div className="topbar-left">
          {/* Hamburger button (always available, crucial on mobile) */}
          <button
            className="hamburger-btn"
            onClick={() => setDrawerOpen(true)}
            title="Abrir menu de navegação e ferramentas"
          >
            <Menu size={18} />
          </button>

          {/* Clean Title / Logo */}
          <div className="brand-wrapper" onClick={() => setTab("chat")}>
            <div className="brandmark-dark">
              <Code2 size={18} />
            </div>
            <div className="brand-title">
              <span>CyberHuntLab</span>
            </div>
          </div>

          {/* Desktop Navigation Tabs (Hidden on Mobile) */}
          <nav className="topbar-tabs">
            <button
              className={tab === "chat" ? "active" : ""}
              onClick={() => setTab("chat")}
            >
              <MessageSquare size={14} />
              Chat
            </button>
            <button
              className={tab === "reverse" ? "active" : ""}
              onClick={() => setTab("reverse")}
            >
              <Zap size={14} />
              Engenharia Reversa & Git
            </button>
            <button
              className={tab === "security" ? "active" : ""}
              onClick={() => setTab("security")}
            >
              <ShieldCheck size={14} />
              Laboratório de Segurança
            </button>
            <button
              className={tab === "skills" ? "active" : ""}
              onClick={() => setTab("skills")}
            >
              <Puzzle size={14} />
              20k Skills
            </button>
            <button
              className={tab === "apresentacao" ? "active" : ""}
              onClick={() => setTab("apresentacao")}
            >
              <Sparkles size={14} />
              Apresentação
            </button>
          </nav>
        </div>

        {/* Desktop Only Actions (Hidden on Mobile) */}
        <div className="topbar-desktop-actions">
          {/* BYOK API Keys Button */}
          <button
            className={`header-btn ${configuredKeysCount > 0 ? "highlight" : ""}`}
            onClick={() => setApiModal(true)}
            title="Conectar chaves de API próprias (Groq, OpenAI, etc.)"
          >
            <Key size={13} />
            <span>Minhas APIs</span>
            {configuredKeysCount > 0 && (
              <span className="brand-tag">
                {configuredKeysCount}
              </span>
            )}
          </button>

          {/* GitHub Connection Button */}
          <button
            className={`header-btn ${githubUser ? "connected" : ""}`}
            onClick={() => setGithubAuthModal(true)}
            title={
              githubUser
                ? `Conectado como @${githubUser.login}`
                : "Autenticar no GitHub com Token"
            }
          >
            {githubUser?.avatar_url ? (
              <img
                src={githubUser.avatar_url}
                alt={githubUser.login}
                style={{ width: 16, height: 16, borderRadius: "50%" }}
              />
            ) : (
              <Github size={13} />
            )}
            <span>{githubUser ? `@${githubUser.login}` : "GitHub"}</span>
          </button>

          {/* Settings */}
          <button
            className="iconbtn"
            onClick={() => { setSettings(true); if (!providerCatalog.length) void loadProviderCatalog(); }}
            title="Configurações gerais"
          >
            <Settings2 size={15} />
          </button>

          <button className="iconbtn" onClick={onLogout} title="Sair do CyberHuntLab">
            <LogOut size={15} />
          </button>
        </div>
      </header>

      {/* ============================================================
          DRAWER / HAMBURGER SLIDEOUT MENU (MOBILE + DESKTOP)
          ============================================================ */}
      {drawerOpen && (
        <div className="drawer-backdrop" onClick={() => setDrawerOpen(false)}>
          <div className="drawer" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-head">
              <div className="brand-wrapper" onClick={() => { setTab("chat"); setDrawerOpen(false); }}>
                <div className="brandmark-dark">
                  <Code2 size={18} />
                </div>
                <div className="brand-title">
                  <span>CyberHuntLab</span>
                </div>
              </div>
              <button className="iconbtn" onClick={() => setDrawerOpen(false)}>
                <X size={16} />
              </button>
            </div>

            {/* New Chat Button */}
            <button className="drawer-newchat" onClick={newChat}>
              <Plus size={16} />
              <span>Novo Chat</span>
            </button>

            {/* Navigation Section (Crucial for Mobile!) */}
            <div className="drawer-nav">
              <div className="drawer-section-label">Navegação Principal</div>
              <button
                className={`drawer-item ${tab === "chat" ? "active" : ""}`}
                onClick={() => {
                  setTab("chat");
                  setDrawerOpen(false);
                }}
              >
                <MessageSquare size={15} />
                <span>Chat OpenCode</span>
                {chats.length > 0 && <span className="badge">{chats.length}</span>}
              </button>

              <button
                className={`drawer-item ${tab === "reverse" ? "active" : ""}`}
                onClick={() => {
                  setTab("reverse");
                  setDrawerOpen(false);
                }}
              >
                <Zap size={15} />
                <span>Engenharia Reversa & Git</span>
              </button>

              <button
                className={`drawer-item ${tab === "security" ? "active" : ""}`}
                onClick={() => {
                  setTab("security");
                  setDrawerOpen(false);
                }}
              >
                <ShieldCheck size={15} />
                <span>CyberHuntLab</span>
              </button>

              <button
                className={`drawer-item ${tab === "skills" ? "active" : ""}`}
                onClick={() => {
                  setTab("skills");
                  setDrawerOpen(false);
                }}
              >
                <Puzzle size={15} />
                <span>Biblioteca de 20k Skills</span>
                <span className="badge">20k</span>
              </button>

              <button
                className={`drawer-item ${tab === "apresentacao" ? "active" : ""}`}
                onClick={() => {
                  setTab("apresentacao");
                  setDrawerOpen(false);
                }}
              >
                <Sparkles size={15} />
                <span>Apresentação CodeCode</span>
              </button>
            </div>

            {/* Saved Chats List */}
            <div className="drawer-section-label">Conversas Salvas</div>
            <div className="drawer-chat-list">
              {sorted.map((c) => (
                <div
                  key={c.id}
                  className={`drawer-chat-item ${active === c.id && tab === "chat" ? "selected" : ""}`}
                  onClick={() => {
                    setActive(c.id);
                    setTab("chat");
                    setDrawerOpen(false);
                  }}
                >
                  <MessageSquare size={13} style={{ flexShrink: 0 }} />
                  <span>{c.title}</span>
                  <button
                    className="chat-del-btn"
                    onClick={(e) => deleteChat(c.id, e)}
                    title="Excluir conversa"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
              {sorted.length === 0 && (
                <div style={{ padding: "8px 10px", color: "var(--text-dim)", fontSize: "11.5px" }}>
                  Nenhuma conversa salva ainda.
                </div>
              )}
            </div>

            {/* Drawer Bottom Actions (Accessible on Mobile) */}
            <div className="drawer-bottom">
              <button
                className="drawer-item"
                onClick={() => {
                  setApiModal(true);
                  setDrawerOpen(false);
                }}
              >
                <Key size={15} />
                <span>Minhas APIs (Groq / OpenAI)</span>
                {configuredKeysCount > 0 && <span className="badge">{configuredKeysCount}</span>}
              </button>

              <button
                className="drawer-item"
                onClick={() => {
                  setGithubAuthModal(true);
                  setDrawerOpen(false);
                }}
              >
                <Github size={15} />
                <span>{githubUser ? `@${githubUser.login}` : "Conectar GitHub"}</span>
              </button>

              <button className="drawer-item" onClick={() => { setDrawerOpen(false); onLogout(); }}>
                <LogOut size={15} />
                <span>Sair do CyberHuntLab</span>
              </button>

              <button
                className="drawer-item"
                onClick={() => {
                  setSettings(true);
                  if (!providerCatalog.length) void loadProviderCatalog();
                  setDrawerOpen(false);
                }}
              >
                <Settings2 size={15} />
                <span>Configurações do Modelo</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          MAIN VIEW AREA
          ============================================================ */}
      <section className="main-view">
        {/* ============================================================
            TAB 1: CHAT COM SUPORTE A GROQ MULTI-MODEL FALLBACK & OPENCODE
            ============================================================ */}
        {tab === "chat" && (
          <>
            <div className="chat-container">
              {current.length === 0 ? (
                <div className="chat-welcome">
                  <div className="chat-welcome-icon">
                    <Code2 size={28} />
                  </div>
                  <h1>O que vamos construir hoje?</h1>
                  <p>
                    OpenCode integrado aos modelos de altíssima velocidade da <b>Groq</b> e ao executor
                    autônomo. Escolha um modelo e envie suas instruções.
                  </p>
                  <div className="chat-suggestions">
                    <button
                      onClick={() =>
                        setInput(
                          "Analise o projeto e implemente uma arquitetura limpa com testes e tratamento de exceções."
                        )
                      }
                    >
                      <Code2 size={15} /> Arquitetura Limpa
                    </button>
                    <button
                      onClick={() =>
                        setInput("Crie um componente full-stack moderno com fallback automático de API.")
                      }
                    >
                      <FolderOpen size={15} /> Componente Full-Stack
                    </button>
                    <button
                      onClick={() =>
                        setInput("Encontre potenciais vazamentos de memória ou limites de rate limit e corrija.")
                      }
                    >
                      <Check size={15} /> Otimizar Rate Limits
                    </button>
                  </div>
                </div>
              ) : (
                <div className="messages-list">
                  {current.map((m) => (
                    <article key={m.id} className={`chat-msg ${m.role}`}>
                      <div className="chat-avatar">
                        {m.role === "user" ? "VC" : <Code2 size={16} />}
                      </div>
                      <div className="chat-msg-body">
                        <div className="chat-msg-role">
                          {m.role === "user" ? "VOCÊ" : "OPENUI CODE CODE"}
                        </div>
                        <div className="chat-msg-text">{m.text}</div>
                        <button
                          className="toolbtn-copy"
                          onClick={() => navigator.clipboard.writeText(m.text)}
                          title="Copiar mensagem"
                        >
                          <Copy size={12} /> Copiar
                        </button>
                        {m.artifact && (
                          <button
                            className="btn-opencode-primary"
                            style={{ marginTop: "10px", width: "max-content" }}
                            onClick={() => downloadWorkspaceZip(m.artifact!.id, m.artifact!.fileName)}
                          >
                            <FolderOpen size={15} /> Baixar {m.artifact.fileName} · {m.artifact.fileCount} arquivos
                          </button>
                        )}
                        {m.status === "error" && (
                          <div className="dark-notice-box warning" style={{ marginTop: "8px", padding: "8px 12px" }}>
                            <AlertCircle size={14} />
                            <span>Erro de execução ou conexão.</span>
                          </div>
                        )}
                      </div>
                    </article>
                  ))}

                  {busy && (
                    <div className="chat-working">
                      <div className="chat-avatar">
                        <Code2 size={16} />
                      </div>
                      <div>
                        <div className="chat-msg-role">OPENUI CODE CODE · EXECUTANDO</div>
                        <div className="chat-typing">
                          <i />
                          <i />
                          <i />
                          <span>{status}{queuedCount > 0 ? ` · ${queuedCount} na fila` : ""}</span>
                        </div>
                      </div>
                    </div>
                  )}
                  <div ref={endRef} />
                </div>
              )}
            </div>

            {/* Dark Composer */}
            <div className="dark-composer-wrap">
              <div className="dark-composer">
                {files.length > 0 && (
                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", paddingBottom: "8px" }}>
                    {files.map((f, i) => (
                      <span
                        key={i}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "5px",
                          background: "var(--panel-elevated)",
                          borderRadius: "6px",
                          padding: "4px 8px",
                          fontSize: "11px",
                          color: "var(--text-secondary)",
                        }}
                      >
                        <Paperclip size={11} />
                        {f.name}
                        <button
                          onClick={() => setFiles((v) => v.filter((_, n) => n !== i))}
                          style={{ border: 0, background: "none", color: "var(--text-dim)", padding: 0 }}
                        >
                          <X size={11} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}

                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      send();
                    }
                  }}
                  placeholder={busy ? "A execução continua. Envie outra instrução para adicioná-la à fila..." : "Descreva o que deseja criar ou alterar no projeto..."}
                  rows={2}
                />

                <div className="composer-bottom">
                  <div className="composer-tools-left">
                    <button
                      className="iconbtn"
                      onClick={() => fileRef.current?.click()}
                      title="Anexar arquivo"
                      style={{ width: "30px", height: "30px" }}
                    >
                      <Plus size={15} />
                    </button>
                    <input
                      ref={fileRef}
                      type="file"
                      multiple
                      hidden
                      onChange={(e) => {
                        if (e.target.files) setFiles((v) => [...v, ...Array.from(e.target.files!)]);
                      }}
                    />

                    {/* Model Selector with Groq & OpenCode options */}
                    <select
                      className="dark-model-select"
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                    >
                      <optgroup label="9Router · Combo de fallback">
                        <option value={routerDefaultModel ? `9router/${routerDefaultModel}` : "9router/auto"} disabled={!routerDefaultModel}>
                          {routerDefaultModel ? `Combo · ${routerDefaultModel}` : "Configure o combo padrão no servidor"}
                        </option>
                      </optgroup>
                      <optgroup label="Modelos Gratuitos Groq (Alta Velocidade)">
                        {MODELS.filter((m) => m.group === "Groq").map((m) => (
                          <option key={m.id} value={m.id}>
                            {m.label}
                          </option>
                        ))}
                      </optgroup>
                      {providerCatalog.map((provider) => (
                        <optgroup key={provider.id} label={`${provider.name}${provider.connected ? " · conectado" : " · não conectado"}`}>
                          {provider.models.map((item) => (
                            <option key={`${provider.id}/${item.id}`} value={`${provider.id}/${item.id}`}>
                              {item.name}{item.free ? " · grátis*" : ""}
                            </option>
                          ))}
                        </optgroup>
                      ))}
                    </select>
                  </div>

                  <button
                    className="dark-send-btn"
                    disabled={!input.trim() && !files.length}
                    onClick={send}
                    title={busy ? "Adicionar à fila sem interromper a execução" : "Enviar mensagem"}
                  >
                    <ArrowUp size={17} />
                  </button>
                </div>
              </div>
            </div>
          </>
        )}

        {/* ============================================================
            TAB 2: ENGENHARIA REVERSA ÉTICA DE ZIP & ENVIO AO GITHUB
            (Bug visual corrigido e validação completa)
            ============================================================ */}
        {tab === "reverse" && (
          <div className="dark-tool-page">
            <div>
              <h1 style={{ fontSize: "22px", color: "#ffffff", display: "flex", alignItems: "center", gap: "10px", margin: "0 0 6px" }}>
                <Zap size={22} style={{ color: "var(--accent-text)" }} /> Engenharia Reversa Ética & Git Trees
              </h1>
              <p style={{ color: "var(--text-muted)", margin: 0, fontSize: "13.5px" }}>
                Análise despersonalizada (Clean-Room) de arquivos ZIP e envio automatizado para o GitHub
                através da Git Trees API com integração ao OpenCode.
              </p>
            </div>

            {/* ZIP File Attachment with Instant Validation */}
            <div className="dark-tool-card">
              <h3>
                <FileCode size={16} /> Arquivo ZIP do Projeto
              </h3>

              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <input
                  ref={zipInputRef}
                  type="file"
                  accept=".zip,application/zip"
                  onChange={(e) => handleZipSelection(e.target.files?.[0] || null)}
                  style={{ display: "none" }}
                />

                <div
                  onClick={() => zipInputRef.current?.click()}
                  style={{
                    border: "2px dashed var(--line-strong)",
                    borderRadius: "12px",
                    padding: "24px 20px",
                    textAlign: "center",
                    cursor: "pointer",
                    background: "var(--bg-subtle)",
                    transition: "all 0.15s ease",
                  }}
                >
                  <UploadCloud size={32} style={{ margin: "0 auto 10px", color: "var(--accent-text)" }} />
                  <div style={{ fontSize: "14px", fontWeight: 600, color: "#ffffff", marginBottom: "4px" }}>
                    {zip ? zip.name : "Clique para selecionar ou arraste o arquivo .zip"}
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                    {zip ? `${(zip.size / 1024 / 1024).toFixed(2)} MB` : "ZIP de até 3 MB nesta versão Vercel"}
                  </div>
                </div>

                {zipValidation && (
                  <div className={`dark-notice-box ${zipValidation.valid ? "info" : "warning"}`}>
                    {zipValidation.valid ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
                    <span>{zipValidation.message}</span>
                  </div>
                )}
              </div>

              {/* Action Buttons for the ZIP */}
              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "6px" }}>
                <button
                  className="btn-opencode-primary"
                  onClick={runReverseEngineering}
                  disabled={!zip || !zipValidation?.valid || reverseBusy}
                >
                  <Sparkles size={15} />
                  {reverseBusy ? "Analisando Clean-Room..." : "Executar Engenharia Reversa Ética"}
                </button>
              </div>
            </div>

            {/* Clean-Room Blueprint Output */}
            {reverseResult && (
              <div className="dark-tool-card" style={{ borderColor: "rgba(249, 115, 22, 0.4)" }}>
                <h3>
                  <Terminal size={16} /> Resultado da Engenharia Reversa (Clean-Room)
                </h3>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "10px" }}>
                  <div className="dark-notice-box neutral">
                    <div>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Framework Detectado</div>
                      <b style={{ color: "#ffffff" }}>{reverseResult.detectedFramework}</b>
                    </div>
                  </div>
                  <div className="dark-notice-box neutral">
                    <div>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Arquivos Analisados</div>
                      <b style={{ color: "#ffffff" }}>{reverseResult.totalFiles} arquivos seguros</b>
                    </div>
                  </div>
                  <div className="dark-notice-box neutral">
                    <div>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)" }}>Componentes</div>
                      <b style={{ color: "#ffffff" }}>{reverseResult.componentsCount} identificados</b>
                    </div>
                  </div>
                </div>

                <div className="dark-notice-box neutral">
                  <ShieldCheck size={16} />
                  <span>A análise técnica está pronta. O ZIP original será enviado diretamente ao agente de projetos; a conversa mostrará apenas o resumo e o link para baixar a nova versão, sem despejar código ou prompts extensos.</span>
                </div>

                <button
                  className="btn-opencode-primary"
                  onClick={sendReversePromptToChat}
                  style={{ width: "max-content" }}
                >
                  <FolderOpen size={15} />
                  Recriar projeto e entregar ZIP
                </button>
              </div>
            )}

            {/* GitHub Trees API Automated Publisher */}
            <div className="dark-tool-card">
              <h3>
                <Github size={16} /> Publicação Automatizada via Git Trees API
              </h3>
              <p style={{ fontSize: "12.5px", color: "var(--text-muted)", margin: 0 }}>
                O GitHub não descompacta ZIPs na API de release. Esta ferramenta descompacta os arquivos em
                memória, cria blobs individuais e comita a árvore completa no seu repositório.
              </p>

              <div className="dark-field-grid">
                <label className="dark-field">
                  <span>Repositório de Destino (owner/nome)</span>
                  <input
                    value={repo}
                    onChange={(e) => setRepo(e.target.value)}
                    placeholder={githubUser ? `${githubUser.login}/meu-projeto-limpo` : "usuario/projeto"}
                  />
                  <span className="hint">Se não existir, será criado automaticamente.</span>
                </label>
                <label className="dark-field">
                  <span>Branch de Destino</span>
                  <input
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    placeholder="main"
                  />
                </label>
              </div>

              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", alignItems: "center" }}>
                <button
                  className="btn-opencode-primary"
                  onClick={publishZip}
                  disabled={githubBusy || !zip || !repo.trim()}
                >
                  <UploadCloud size={15} />
                  {githubBusy ? "Publicando via Git Trees API..." : "Descompactar e Publicar no GitHub"}
                </button>

                {githubUser && (
                  <button
                    className="header-btn"
                    onClick={() => setRepo(`${githubUser.login}/`)}
                  >
                    Usar @{githubUser.login}/
                  </button>
                )}
              </div>

              {publishNotice && (
                <div
                  className={`dark-notice-box ${
                    publishNotice.includes("Sucesso") || publishNotice.includes("sucesso")
                      ? "info"
                      : "neutral"
                  }`}
                >
                  {publishNotice}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================
            CYBERHUNTLAB — ZIP SECURITY WORKBENCH
            ============================================================ */}
        {tab === "security" && (
          <div className="dark-tool-page">
            <div>
              <h1 style={{ fontSize: "23px", color: "#ffffff", display: "flex", alignItems: "center", gap: "10px", margin: "0 0 6px" }}>
                <ShieldCheck size={23} style={{ color: "var(--accent-text)" }} /> CyberHuntLab
              </h1>
              <p style={{ color: "var(--text-muted)", margin: 0, fontSize: "13.5px" }}>
                Laboratório de análise de segurança para projetos, aplicações, Kubernetes, Docker, Terraform e configurações Vercel.
              </p>
            </div>
            <div className="dark-tool-card">
              <h3><UploadCloud size={16} /> Analisar projeto compactado (.zip)</h3>
              <p style={{ color: "var(--text-muted)", fontSize: "12.5px", margin: "0 0 12px" }}>
                Envie um ZIP de um projeto que você possui ou está autorizado a avaliar. O laboratório inspeciona código e arquivos de configuração sem executar o conteúdo.
              </p>
              <input ref={zipInputRef} type="file" accept=".zip,application/zip" onChange={(e) => handleZipSelection(e.target.files?.[0] || null)} style={{ display: "none" }} />
              <div onClick={() => zipInputRef.current?.click()} style={{ border: "2px dashed var(--line-strong)", borderRadius: "12px", padding: "24px 20px", textAlign: "center", cursor: "pointer", background: "var(--bg-subtle)" }}>
                <UploadCloud size={30} style={{ margin: "0 auto 8px", color: "var(--accent-text)" }} />
                <div style={{ color: "#fff", fontSize: "14px", fontWeight: 600 }}>{zip ? zip.name : "Selecionar ZIP do GitHub ou projeto local"}</div>
                <div style={{ color: "var(--text-dim)", fontSize: "12px", marginTop: "4px" }}>{zip ? `${(zip.size / 1024 / 1024).toFixed(2)} MB` : "Limite atual: 3 MB compactados na implantação Vercel"}</div>
              </div>
              {zipValidation && <div className={`dark-notice-box ${zipValidation.valid ? "info" : "warning"}`} style={{ marginTop: 10 }}><span>{zipValidation.message}</span></div>}
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 14 }}>
                <button className="btn-opencode-primary" onClick={runSecurityAudit} disabled={!zip || !zipValidation?.valid || securityBusy}>
                  <ShieldCheck size={15} /> {securityBusy ? "Analisando arquivos..." : "Executar auditoria de segurança"}
                </button>
                <button className="header-btn" onClick={() => { setZip(null); setZipValidation(null); setSecurityReport(null); if (zipInputRef.current) zipInputRef.current.value = ""; }}>Limpar</button>
              </div>
            </div>
            {securityReport && (
              <div className="dark-tool-card" style={{ borderColor: "rgba(249, 115, 22, 0.4)" }}>
                <h3><ShieldCheck size={16} /> Relatório de segurança — {securityReport.fileName}</h3>
                <p style={{ color: "var(--text-muted)", fontSize: 12, margin: "-4px 0 12px" }}>Tecnologia detectada: <b style={{ color: "#fff" }}>{securityReport.framework}</b> · Análise estática · {new Date(securityReport.analyzedAt).toLocaleString("pt-BR")}</p>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 8 }}>
                  <div className="dark-notice-box neutral">Arquivos: <b>{securityReport.summary.files}</b></div>
                  <div className="dark-notice-box neutral">Dependências: <b>{securityReport.summary.dependencies}</b></div>
                  <div className="dark-notice-box neutral">Achados: <b>{securityReport.summary.findings}</b></div>
                  <div className="dark-notice-box neutral">Kubernetes: <b>{securityReport.inventory.kubernetes.length}</b></div>
                </div>
                {securityReport.integrity && (
                  <div className="dark-notice-box neutral" style={{ marginTop: 8, display: "block", fontSize: 11.5, wordBreak: "break-all" }}>
                    <b>Integridade (SHA-256 do ZIP):</b> <code>{securityReport.integrity.archiveSha256}</code>
                    <div style={{ color: "var(--text-dim)", marginTop: 4 }}>{securityReport.integrity.files.length} arquivos com hash · {securityReport.integrity.notHashed.length} não lidos (sensíveis ou grandes) · {(securityReport.integrity.bytesDecompressed / 1024).toFixed(0)} KB descompactados</div>
                  </div>
                )}
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "12px 0" }}>
                  {(["critical", "high", "medium", "low", "info"] as const).map((level) => <span key={level} className="dark-notice-box neutral" style={{ padding: "7px 10px" }}>{level.toUpperCase()}: <b>{securityReport.summary.severityCounts[level]}</b></span>)}
                </div>
                {securityReport.summary.statusCounts && (
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "0 0 12px" }}>
                    {FINDING_STATUSES.map((st) => <span key={st} className="dark-notice-box neutral" style={{ padding: "5px 9px", fontSize: 11 }}>{STATUS_LABELS[st]}: <b>{securityReport.summary.statusCounts[st] ?? 0}</b></span>)}
                  </div>
                )}
                {securityReport.findings.length === 0 ? <div className="dark-notice-box info">Nenhum indicador coberto pelas regras atuais foi encontrado. Isso não significa que o projeto esteja livre de vulnerabilidades.</div> : (
                  <div style={{ display: "grid", gap: 9 }}>
                    {securityReport.findings.map((finding: any) => (
                      <div key={finding.id} style={{ border: "1px solid var(--line-strong)", borderRadius: 10, padding: 12, background: "var(--bg-subtle)" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}><b style={{ color: "#fff", fontSize: 13 }}>{finding.title}</b><span style={{ fontSize: 10, fontWeight: 700, color: finding.severity === "critical" || finding.severity === "high" ? "#fb7185" : "var(--accent-text)" }}>{finding.severity.toUpperCase()}</span></div>
                        <div style={{ color: "var(--accent-text)", fontSize: 11, marginTop: 5 }}>
                          {finding.id} · {finding.file}{finding.line ? `:${finding.line}` : ""} · {finding.category}{finding.cwe ? ` · ${finding.cwe}` : ""}
                        </div>
                        {finding.confidence && (
                          <div style={{ fontSize: 11, marginTop: 4, color: "var(--text-dim)" }}>
                            Confiança da regra: <b style={{ color: "#fff" }}>{CONFIDENCE_LABELS[finding.confidence as "high" | "medium" | "low"]}</b> · Estado: <b style={{ color: finding.status === "VALIDATED" ? "#4ade80" : finding.status === "FALSE_POSITIVE" ? "var(--text-dim)" : "#fff" }}>{STATUS_LABELS[finding.status as FindingStatus] || finding.status}</b>
                          </div>
                        )}
                        <p style={{ color: "var(--text-muted)", fontSize: 12, margin: "7px 0" }}>{finding.evidence}</p>
                        <p style={{ color: "#d1d5db", fontSize: 12, margin: 0 }}><b>Recomendação:</b> {finding.recommendation}</p>
                        {finding.fileSha256 && <div style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 6, wordBreak: "break-all" }}>SHA-256 do arquivo: <code>{finding.fileSha256}</code></div>}
                        {finding.status && (
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
                            <input
                              value={findingNotes[finding.id] || ""}
                              onChange={(e) => setFindingNotes((notes) => ({ ...notes, [finding.id]: e.target.value }))}
                              placeholder="Nota da validação (opcional)"
                              style={{ flex: "1 1 180px", fontSize: 11.5, padding: "5px 8px" }}
                            />
                            <select
                              value=""
                              onChange={(e) => { if (e.target.value) updateFindingStatus(finding.id, e.target.value as FindingStatus); }}
                              style={{ fontSize: 11.5, padding: "5px 8px" }}
                              title="Registrar decisão do pesquisador"
                            >
                              <option value="">Mudar estado…</option>
                              {FINDING_STATUSES.filter((st) => st !== "DETECTED" && st !== finding.status).map((st) => <option key={st} value={st}>{STATUS_LABELS[st]}</option>)}
                            </select>
                          </div>
                        )}
                        {Array.isArray(finding.history) && finding.history.length > 1 && (
                          <div style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 6 }}>
                            Histórico: {finding.history.map((h: any) => `${STATUS_LABELS[h.status as FindingStatus] || h.status} (${h.by === "researcher" ? "pesquisador" : "analisador"}${h.note ? `: ${h.note}` : ""})`).join(" → ")}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 14 }}>
                  <button className="btn-opencode-primary" onClick={sendSecurityReportToAI}><Sparkles size={15} /> Analisar achados com IA</button>
                  <button className="header-btn" onClick={exportSecurityReport}>Exportar relatório JSON</button>
                </div>
                <div className="dark-notice-box warning" style={{ marginTop: 12, display: "block" }}>
                  <b>Limitações importantes</b>
                  <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>{securityReport.limitations.map((item: string, index: number) => <li key={index}>{item}</li>)}</ul>
                </div>
              </div>
            )}
            <div className="dark-tool-card">
              <h3><Layers size={16} /> Escopo do laboratório</h3>
              <p style={{ color: "var(--text-muted)", fontSize: 12.5, margin: 0 }}>A auditoria inicial cobre padrões estáticos em código, segredos acidentalmente incluídos, dependências declaradas, Docker, Kubernetes, Terraform e presença de configuração Vercel. Próximas etapas podem adicionar análise de lockfiles com OSV, Trivy, Semgrep e execução isolada na VPS.</p>
            </div>
          </div>
        )}

        {/* ============================================================
            TAB 3: BIBLIOTECA DE 20 MIL SKILLS (PROGRESSIVE DISCLOSURE)
            ============================================================ */}
        {tab === "skills" && (
          <div className="dark-tool-page">
            <div>
              <h1 style={{ fontSize: "22px", color: "#ffffff", display: "flex", alignItems: "center", gap: "10px", margin: "0 0 6px" }}>
                <Puzzle size={22} style={{ color: "var(--accent-text)" }} /> Biblioteca de 20.000 Skills
              </h1>
              <p style={{ color: "var(--text-muted)", margin: 0, fontSize: "13.5px" }}>
                Arquitetura de <b>Divulgação Progressiva</b>: os metadados leves são pesquisados instantaneamente,
                e o corpo integral (markdown + scripts) só é injetado no prompt quando a skill é acionada.
              </p>
            </div>

            {/* Filter & Search Bar */}
            <div className="dark-tool-card">
              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                <input
                  value={skillQuery}
                  onChange={(e) => {
                    setSkillQuery(e.target.value);
                    loadSkills(1, e.target.value, skillCategory);
                  }}
                  placeholder="Pesquisar entre as 20.000 habilidades (ex: reverse, groq, postgres, clean-room)..."
                  style={{ flex: 1, minWidth: "240px" }}
                />

                <select
                  value={skillCategory}
                  onChange={(e) => {
                    setSkillCategory(e.target.value);
                    loadSkills(1, skillQuery, e.target.value);
                  }}
                  style={{ width: "auto" }}
                >
                  {SKILL_CATEGORIES.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>

                <button
                  className="header-btn"
                  onClick={() => loadSkills(1, skillQuery, skillCategory)}
                >
                  <RefreshCw size={13} /> Atualizar
                </button>
              </div>

              <div style={{ fontSize: "12px", color: "var(--text-dim)" }}>
                Mostrando página {skillsPage} de {Math.ceil(skillsTotal / 24)} ({skillsTotal.toLocaleString("pt-BR")} habilidades indexadas)
              </div>
            </div>

            {/* Skills Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "12px" }}>
              {skills.map((s) => (
                <div
                  key={s.id}
                  className="dark-tool-card"
                  style={{ padding: "16px", cursor: "pointer" }}
                  onClick={() => inspectSkillDetail(s.id)}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "8px" }}>
                    <b style={{ color: "#ffffff", fontSize: "13.5px" }}>{s.name}</b>
                    <span className="dark-tag">{s.category || "Skill"}</span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: "4px 0 8px", lineHeight: "1.4" }}>
                    {s.description}
                  </p>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "auto" }}>
                    <span style={{ fontSize: "10.5px", color: "var(--text-dim)", fontFamily: "monospace" }}>
                      v{s.version || "1.0.0"}
                    </span>
                    <span style={{ fontSize: "11px", color: "var(--accent-text)", display: "flex", alignItems: "center", gap: "3px" }}>
                      Ver detalhes <ChevronRight size={12} />
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination */}
            <div style={{ display: "flex", justifyContent: "center", gap: "8px", marginTop: "10px" }}>
              <button
                className="header-btn"
                disabled={skillsPage <= 1}
                onClick={() => loadSkills(skillsPage - 1, skillQuery, skillCategory)}
              >
                Anterior
              </button>
              <button
                className="header-btn"
                disabled={skillsPage >= Math.ceil(skillsTotal / 24)}
                onClick={() => loadSkills(skillsPage + 1, skillQuery, skillCategory)}
              >
                Próxima
              </button>
            </div>
          </div>
        )}

        {/* ============================================================
            TAB 4: PÁGINA DE APRESENTAÇÃO (OpenUI Code Code)
            ============================================================ */}
        {tab === "apresentacao" && (
          <div className="presentation-container">
            <div className="presentation-hero">
              <div className="presentation-badge">
                <i />
                OPENCODE COMPANION · WEB UI
              </div>

              <h1 className="presentation-title">OpenUI Code Code</h1>

              <p className="presentation-subtitle">
                A interface visual definitiva para o ecossistema <b>OpenCode</b>. Equipada com múltiplos modelos
                de altíssima velocidade da <b>Groq</b>, engenharia reversa ética (clean-room), publicação via Git Trees
                e biblioteca para <b>20.000 skills</b>.
              </p>

              <div className="presentation-actions">
                <button
                  className="btn-opencode-primary"
                  onClick={() => setTab("chat")}
                >
                  <MessageSquare size={16} />
                  Abrir Chat do CodeCode
                </button>

                <button
                  className="btn-opencode-secondary"
                  onClick={() => setApiModal(true)}
                >
                  <Key size={15} />
                  Configurar Minhas APIs (BYOK)
                </button>

                <a
                  href="https://github.com/opencode-ai/opencode"
                  target="_blank"
                  rel="noreferrer"
                  className="btn-opencode-secondary"
                >
                  <Github size={15} />
                  github.com/OpenCode <ExternalLink size={12} />
                </a>
              </div>

              <div className="presentation-socials">
                <a href="https://github.com/ticarollamas-arch" target="_blank" rel="noreferrer" className="social-link">
                  <Github size={17} /> <span>GitHub · @ticarollamas-arch</span> <ExternalLink size={12} />
                </a>
                <a href="https://www.instagram.com/anacarolinelamas/" target="_blank" rel="noreferrer" className="social-link instagram-link">
                  <Instagram size={17} /> <span>Instagram · @anacarolinelamas</span> <ExternalLink size={12} />
                </a>
              </div>
            </div>

            <section className="tech-showcase" aria-label="Tecnologias utilizadas">
              <div className="section-eyebrow">TECNOLOGIAS E ECOSSISTEMA</div>
              <h2>Ferramentas para construir, integrar e evoluir</h2>
              <p>Um espaço de trabalho conectado às tecnologias modernas de desenvolvimento, infraestrutura e inteligência artificial.</p>
              <div className="tech-grid">
                {[
                  ["Docker", "🐳", "docker"], ["Node.js", "JS", "node"], ["Java", "☕", "java"],
                  ["AWS", "aws", "aws"], ["GitHub", "⌘", "github"], ["Python", "Py", "python"],
                  ["React", "⚛", "react"], ["Next.js", "N", "next"], ["Linux", "🐧", "linux"],
                  ["TypeScript", "TS", "typescript"], ["PostgreSQL", "◉", "postgres"], ["Vercel", "▲", "vercel"]
                ].map(([name, mark, tone], index) => (
                  <div className={`tech-tile tech-${tone}`} key={name} style={{ animationDelay: `${index * 55}ms` }}>
                    <span className="tech-mark">{mark}</span><span>{name}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="token-savings-section">
              <div className="section-eyebrow">EFICIÊNCIA DE CONTEXTO</div>
              <h2>Economia inteligente de tokens</h2>
              <p>Conheça ferramentas open source que ajudam a reduzir contexto redundante, compactar saídas e aproveitar melhor a janela de cada modelo. Os resultados variam conforme o projeto e a tarefa.</p>
              <a className="token-repo-card" href="https://github.com/rtk-ai/rtk" target="_blank" rel="noreferrer">
                <span className="token-repo-icon"><Zap size={21}/></span>
                <span><b>RTK · Rust Token Killer</b><small>Filtra e compacta saídas de comandos de desenvolvimento antes que cheguem ao contexto da IA; o projeto oferece integração com OpenCode.</small><em>github.com/rtk-ai/rtk</em></span>
                <ExternalLink size={15}/>
              </a>
              <p className="token-repo-note">Referência open source de economia de tokens com suporte ao OpenCode. Se o vídeo do Instagram mencionar outro projeto, posso trocar pelo repositório exato quando você enviar o perfil ou o link.</p>
            </section>

            {/* Official OpenCode Credits Banner */}
            <div className="credits-banner">
              <div className="credits-banner-text">
                <h3>
                  <Sparkles size={17} style={{ color: "var(--accent-text)" }} />
                  Créditos e Reconhecimento ao OpenCode
                </h3>
                <p>
                  O <b>OpenUI Code Code</b> foi concebido em homenagem e como cliente visual para o ecossistema{" "}
                  <b>OpenCode</b>. Todos os méritos de motor de agente são atribuídos ao projeto oficial.
                </p>
              </div>
              <a
                href="https://github.com/opencode-ai/opencode"
                target="_blank"
                rel="noreferrer"
                className="credits-link-btn"
              >
                <Github size={14} /> github.com/OpenCode <ExternalLink size={12} />
              </a>
            </div>

            {/* 4 Feature Cards */}
            <div className="features-grid">
              <div className="feature-card">
                <div className="feature-icon-wrap">
                  <Zap size={18} />
                </div>
                <h4>Modelos Groq & Fallback</h4>
                <p>
                  Integração ultra-rápida com Llama 3.3 70B, QwQ e Mixtral com transição automática transparente
                  ao atingir limites de rate limit (RPM/RPD).
                </p>
              </div>

              <div className="feature-card">
                <div className="feature-icon-wrap">
                  <ShieldCheck size={18} />
                </div>
                <h4>Engenharia Reversa Clean-Room</h4>
                <p>
                  Extração segura de ZIPs e geração de especificações funcionais despersonalizadas, livres de marcas
                  proprietárias e prontas para recriação.
                </p>
              </div>

              <div className="feature-card">
                <div className="feature-icon-wrap">
                  <UploadCloud size={18} />
                </div>
                <h4>Git Trees API Automatizada</h4>
                <p>
                  Descompactação direta no servidor e commit estruturado na árvore Git sem exigir clone local ou
                  tentar enviar ZIP bruto.
                </p>
              </div>

              <div className="feature-card">
                <div className="feature-icon-wrap">
                  <Layers size={18} />
                </div>
                <h4>20.000 Skills Progressivas</h4>
                <p>
                  Arquitetura de divulgação progressiva que preserva a janela de contexto de tokens, carregando
                  instruções completas somente sob demanda.
                </p>
              </div>
            </div>

            <section className="about-details">
              <div className="about-detail-card">
                <h3>Uma interface visual para trabalhar com código</h3>
                <p>O objetivo é aproximar ferramentas poderosas de desenvolvimento de quem prefere uma experiência visual, organizada e acessível pelo navegador — sem depender de executar cada tarefa manualmente no terminal.</p>
              </div>
              <div className="about-detail-card">
                <h3>Conteúdo, demonstrações e aprendizado</h3>
                <p>Também estou preparando demonstrações em vídeo com explicações em áudio, apresentando repositórios, ferramentas e fluxos de trabalho de forma prática. Novidades e materiais serão compartilhados por aqui e nas redes sociais.</p>
              </div>
              <div className="about-detail-card">
                <h3>Desenvolvimento responsável</h3>
                <p>Os recursos de análise e engenharia reversa devem ser utilizados em projetos próprios ou com autorização. A proposta é facilitar o entendimento técnico, a organização do código e a criação de soluções.</p>
              </div>
            </section>
          </div>
        )}
      </section>

      {/* ============================================================
          MODAL 1: BYOK - GERENCIADOR DE CHAVES DE API (GROQ / OPENAI)
          ============================================================ */}
      {apiModal && (
        <div className="dark-modal-backdrop" onClick={() => setApiModal(false)}>
          <div className="dark-modal" onClick={(e) => e.stopPropagation()}>
            <div className="dark-modal-head">
              <div>
                <h2>
                  <Key size={18} style={{ color: "var(--accent-text)" }} /> Minhas Chaves de API (BYOK)
                </h2>
                <p>
                  As chaves são enviadas uma única vez ao servidor, cifradas (AES-256-GCM) e guardadas num cookie
                  HttpOnly. O JavaScript da página não consegue lê-las e elas não ficam no localStorage.
                </p>
              </div>
              <button className="iconbtn" onClick={() => setApiModal(false)}>
                <X size={16} />
              </button>
            </div>

            {/* Groq Key */}
            <div className="dark-modal-section">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <label style={{ margin: 0 }}>Chave Groq API (gsk_...)</label>
                <a
                  href="https://console.groq.com/keys"
                  target="_blank"
                  rel="noreferrer"
                  style={{ fontSize: "11px", color: "var(--accent-text)", textDecoration: "none" }}
                >
                  Obter chave grátis na Groq ↗
                </a>
              </div>
              <input
                type="password"
                value={apiKeys.groq}
                onChange={(e) => setApiKeys({ ...apiKeys, groq: e.target.value })}
                placeholder={credStatus.groq ? "•••••••• configurada no servidor (digite para substituir)" : "gsk_..."}
                autoComplete="off"
              />
              <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                Conecta sua conta Groq. O catálogo e o fallback usam modelos atualmente ativos na API oficial.
              </span>
              {credStatus.groq && <button type="button" className="header-btn" style={{ width: "max-content", fontSize: 11 }} onClick={() => void removeCredential("groq")}><Trash2 size={11} /> Remover chave Groq</button>}
            </div>

            {/* OpenAI Key */}
            <div className="dark-modal-section">
              <label>Chave OpenAI API (sk-...)</label>
              <input
                type="password"
                value={apiKeys.openai}
                onChange={(e) => setApiKeys({ ...apiKeys, openai: e.target.value })}
                placeholder={credStatus.openai ? "•••••••• configurada no servidor" : "sk-proj-..."}
                autoComplete="off"
              />
              <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Guardada para a fase de IA; ainda não é usada pelas rotas atuais.</span>
              {credStatus.openai && <button type="button" className="header-btn" style={{ width: "max-content", fontSize: 11 }} onClick={() => void removeCredential("openai")}><Trash2 size={11} /> Remover</button>}
            </div>

            {/* Gemini Key */}
            <div className="dark-modal-section">
              <label>Chave Google Gemini API (AIza...)</label>
              <input
                type="password"
                value={apiKeys.gemini}
                onChange={(e) => setApiKeys({ ...apiKeys, gemini: e.target.value })}
                placeholder={credStatus.gemini ? "•••••••• configurada no servidor" : "AIzaSy..."}
                autoComplete="off"
              />
              <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>Guardada para a fase de IA; ainda não é usada pelas rotas atuais.</span>
              {credStatus.gemini && <button type="button" className="header-btn" style={{ width: "max-content", fontSize: 11 }} onClick={() => void removeCredential("gemini")}><Trash2 size={11} /> Remover</button>}
            </div>

            {/* Custom OpenCode Server Endpoint */}
            <div className="dark-modal-section">
              <label>URL do Servidor OpenCode Privado (Opcional)</label>
              <input
                type="text"
                value={apiKeys.customServerUrl}
                onChange={(e) => setApiKeys({ ...apiKeys, customServerUrl: e.target.value })}
                placeholder={credStatus.opencode ? `Atual: ${credStatus.opencode.url}` : "https://meu-opencode.exemplo.com"}
              />
              <span style={{ fontSize: "11px", color: "var(--text-dim)" }}>
                Por segurança (anti-SSRF), só são aceitos hosts liberados pela administração em OPENCODE_ALLOWED_HOSTS.
              </span>
              <label style={{ marginTop: "6px" }}>Senha do Servidor OpenCode</label>
              <input
                type="password"
                value={apiKeys.customServerPassword}
                onChange={(e) => setApiKeys({ ...apiKeys, customServerPassword: e.target.value })}
                placeholder={credStatus.opencode?.hasPassword ? "•••••••• configurada no servidor" : "Senha de acesso ao executor"}
              />
              {credStatus.opencode && <button type="button" className="header-btn" style={{ width: "max-content", fontSize: 11, marginTop: 6 }} onClick={() => { void removeCredential("opencode").then(() => loadProviderCatalog()); }}><Trash2 size={11} /> Voltar ao servidor OpenCode padrão</button>}
            </div>

            {apiSaveError && <div className="dark-notice-box error" style={{ marginBottom: "12px" }}><AlertCircle size={15} /><span>{apiSaveError}</span></div>}
            {apiSavedNotice && (
              <div className="dark-notice-box info" style={{ marginBottom: "12px" }}>
                <CheckCircle2 size={15} />
                <span>Credenciais cifradas e salvas no servidor. A chave Groq foi validada antes de salvar.</span>
              </div>
            )}

            <div className="dark-modal-foot">
              <button className="header-btn" onClick={() => setApiModal(false)}>
                Fechar
              </button>
              <button className="header-btn" onClick={onLogout} title="Encerrar a sessão do CyberHuntLab">
                <LogOut size={13} /> Sair
              </button>
              <button className="btn-opencode-primary" onClick={saveCustomApiKeys}>
                <Check size={14} /> Salvar Chaves
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          MODAL 2: GITHUB AUTHENTICATION
          ============================================================ */}
      {githubAuthModal && (
        <div className="dark-modal-backdrop" onClick={() => setGithubAuthModal(false)}>
          <div className="dark-modal" onClick={(e) => e.stopPropagation()}>
            <div className="dark-modal-head">
              <div>
                <h2>
                  <Github size={18} /> Autenticar no GitHub
                </h2>
                <p>
                  Gere um Personal Access Token único no GitHub com permissão <code>repo</code> para publicar
                  projetos automaticamente. O token é validado e cifrado no servidor; não fica no navegador.
                </p>
              </div>
              <button className="iconbtn" onClick={() => setGithubAuthModal(false)}>
                <X size={16} />
              </button>
            </div>

            {githubUser && (
              <div
                className="dark-modal-section"
                style={{
                  background: "rgba(34, 197, 94, 0.1)",
                  borderColor: "rgba(34, 197, 94, 0.3)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <img
                    src={githubUser.avatar_url}
                    alt={githubUser.login}
                    style={{ width: 40, height: 40, borderRadius: "50%", border: "2px solid #22c55e" }}
                  />
                  <div>
                    <div style={{ fontSize: "13.5px", fontWeight: "700", color: "#4ade80" }}>
                      Conectado como @{githubUser.login}
                    </div>
                    <div style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>
                      {githubUser.name ? `${githubUser.name} · ` : ""}
                      {githubUser.public_repos !== undefined ? `${githubUser.public_repos} repositórios` : "Autenticado"}
                    </div>
                  </div>
                </div>
                <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                  <a
                    href={githubUser.html_url}
                    target="_blank"
                    rel="noreferrer"
                    className="header-btn"
                    style={{ fontSize: "11.5px", textDecoration: "none" }}
                  >
                    Ver perfil <ExternalLink size={11} />
                  </a>
                  <button
                    className="header-btn"
                    onClick={disconnectGitHub}
                    style={{ color: "#ef4444", borderColor: "rgba(239, 68, 68, 0.3)" }}
                  >
                    <LogOut size={12} /> Desconectar
                  </button>
                </div>
              </div>
            )}

            <div className="dark-modal-section">
              <div style={{ fontSize: "12.5px", fontWeight: 700, color: "#ffffff", display: "flex", alignItems: "center", gap: "6px" }}>
                <span className="brand-tag">PASSO 1</span> Gerar token no GitHub
              </div>
              <p style={{ fontSize: "12px", color: "var(--text-muted)", margin: 0 }}>
                Clique para abrir a página do GitHub com as permissões pré-configuradas:
              </p>
              <a
                href="https://github.com/settings/tokens/new?scopes=repo,read:user,user:email&description=OpenCode+Workspace"
                target="_blank"
                rel="noreferrer"
                className="header-btn highlight"
                style={{ width: "max-content", textDecoration: "none" }}
              >
                <Github size={14} />
                Abrir página de tokens do GitHub <ExternalLink size={12} />
              </a>
            </div>

            <div className="dark-modal-section">
              <div style={{ fontSize: "12.5px", fontWeight: 700, color: "#ffffff", display: "flex", alignItems: "center", gap: "6px" }}>
                <span className="brand-tag">PASSO 2</span> Cole o token pessoal
              </div>
              <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
                <input
                  type={showToken ? "text" : "password"}
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value)}
                  placeholder="ghp_... ou github_pat_..."
                  autoComplete="off"
                  spellCheck={false}
                  style={{ paddingRight: "40px" }}
                />
                <button
                  type="button"
                  onClick={() => setShowToken(!showToken)}
                  style={{
                    position: "absolute",
                    right: "10px",
                    background: "none",
                    border: 0,
                    color: "var(--text-dim)",
                    cursor: "pointer",
                  }}
                >
                  {showToken ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {authFeedback && (
              <div
                className={`dark-notice-box ${
                  authFeedback.type === "success" ? "info" : "warning"
                }`}
                style={{ marginBottom: "10px" }}
              >
                {authFeedback.type === "success" ? <Check size={15} /> : <AlertCircle size={15} />}
                <span>{authFeedback.text}</span>
              </div>
            )}

            <div className="dark-modal-foot">
              <button className="header-btn" onClick={() => setGithubAuthModal(false)}>
                Fechar
              </button>
              <button
                className="btn-opencode-primary"
                onClick={connectGitHubToken}
                disabled={verifyingToken || !tokenInput.trim()}
              >
                <Key size={13} />
                {verifyingToken ? "Verificando..." : "Conectar Token"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          MODAL 3: SKILL LEVEL 2 DETAIL (PROGRESSIVE DISCLOSURE)
          ============================================================ */}
      {selectedSkillDetail && (
        <div className="dark-modal-backdrop" onClick={() => setSelectedSkillDetail(null)}>
          <div className="dark-modal" style={{ maxWidth: "680px" }} onClick={(e) => e.stopPropagation()}>
            <div className="dark-modal-head">
              <div>
                <h2>
                  <Puzzle size={18} style={{ color: "var(--accent-text)" }} /> {selectedSkillDetail.name}
                </h2>
                <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "4px" }}>
                  <span className="dark-tag">{selectedSkillDetail.category}</span>
                  <span style={{ fontSize: "11px", color: "var(--text-dim)", fontFamily: "monospace" }}>
                    ID: {selectedSkillDetail.id}
                  </span>
                </div>
              </div>
              <button className="iconbtn" onClick={() => setSelectedSkillDetail(null)}>
                <X size={16} />
              </button>
            </div>

            <div style={{ marginBottom: "16px" }}>
              <div style={{ fontSize: "12.5px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "6px" }}>
                Corpo Completo da Habilidade (SKILL.md - Injetado sob demanda):
              </div>
              <pre
                style={{
                  background: "var(--bg-subtle)",
                  border: "1px solid var(--line)",
                  borderRadius: "10px",
                  padding: "12px",
                  fontSize: "12px",
                  lineHeight: "1.5",
                  maxHeight: "260px",
                  overflowY: "auto",
                  color: "#e2e8f0",
                }}
              >
                {selectedSkillDetail.fullMarkdown}
              </pre>
            </div>

            <div className="dark-modal-foot">
              <button className="header-btn" onClick={() => setSelectedSkillDetail(null)}>
                Fechar
              </button>
              <button
                className="btn-opencode-primary"
                onClick={() => injectSkillIntoChat(selectedSkillDetail.promptSnippet)}
              >
                <Terminal size={14} /> Injetar no Prompt do Chat
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================
          MODAL 4: CONFIGURAÇÕES
          ============================================================ */}
      {settings && (
        <div className="dark-modal-backdrop" onClick={() => setSettings(false)}>
          <div className="dark-modal model-settings-modal" onClick={(e) => e.stopPropagation()}>
            <div className="dark-modal-head">
              <div>
                <h2><Settings2 size={18} /> Central de modelos e roteamento</h2>
                <p>Pesquise, conecte provedores e escolha o modelo sem abrir o terminal.</p>
              </div>
              <button className="iconbtn" onClick={() => setSettings(false)}><X size={16} /></button>
            </div>

            <div className="model-console">
              <div className="model-console-bar">
                <span className="console-dot" /><span className="console-dot" /><span className="console-dot" />
                <span className="console-path">OpenCode / models / providers</span>
                <span className="console-live">CATÁLOGO</span>
              </div>
              <label className="model-search-box">
                <Search size={17} />
                <input value={providerSearch} onChange={(e) => setProviderSearch(e.target.value)} placeholder="> buscar modelos ou provedores..." />
                <kbd>⌕</kbd>
              </label>
              <div className="model-console-actions">
                <button className="header-btn" onClick={loadProviderCatalog} disabled={providerLoading || routerBusy}>
                  <RefreshCw size={14} className={providerLoading ? "spin" : ""} /> {providerLoading ? "Buscando..." : "Carregar modelos"}
                </button>
                <button className="header-btn" onClick={syncNineRouter} disabled={routerBusy}>
                  <RefreshCw size={14} className={routerBusy ? "spin" : ""} /> Sincronizar 9Router
                </button>
                <button className="btn-opencode-primary" onClick={startNineRouter} disabled={routerBusy}>
                  <Zap size={14} /> {routerBusy ? "Conectando..." : routerDefaultModel && model === `9router/${routerDefaultModel}` && routerStatus === "ready" ? "9Router ativo" : "Start 9Router"}
                </button>
                <span><Database size={13} /> OpenCode + 9Router</span>
              </div>
              <div className="dark-notice-box neutral" style={{ marginTop: 10 }}>
                <Zap size={15} style={{ flexShrink: 0 }} />
                <div><b>9Router:</b> {routerStatus === "ready" ? "Conectado. O combo selecionado executa fallback ou rotação conforme a estratégia configurada no 9Router." : routerStatus === "offline" ? "Configurado, mas indisponível. Confira a conexão do serviço no VPS." : "Aguardando configuração do serviço no servidor."} <small>As credenciais dos provedores ficam no 9Router do servidor; o usuário final não precisa cadastrar sua própria API. O Start conecta ao serviço já instalado; não instala nem inicia o processo do 9Router.</small></div>
              </div>
              {routerFeedback && <p className="provider-feedback">{routerFeedback}</p>}
            </div>

            {providerError && <div className="dark-notice-box neutral" style={{ marginTop: 12 }}><AlertCircle size={16} /> <div>{providerError}<br /><small>Verifique se o OpenCode está ativo e se OPENCODE_SERVER_URL aponta para ele.</small></div></div>}

            <div className="provider-manager-grid">
              <section className="provider-list-panel">
                <div className="provider-panel-title"><b><PlugZap size={15} /> Provedores</b><span>{visibleProviders.length} disponíveis</span></div>
                {providerLoading && <p className="provider-empty">Consultando o servidor OpenCode...</p>}
                {!providerLoading && visibleProviders.map((provider) => (
                  <button key={provider.id} className={`provider-row ${activeProvider === provider.id ? "active" : ""}`} onClick={() => { setActiveProvider(provider.id); setProviderFeedback(""); }}>
                    <span className="provider-avatar">{provider.name.slice(0, 1).toUpperCase()}</span>
                    <span className="provider-row-copy"><b>{provider.name}</b><small>{provider.models.length} modelos · {provider.id}</small></span>
                    <span className={`provider-state ${provider.connected ? "connected" : ""}`}>{provider.connected ? "Conectado" : "Disponível"}</span>
                  </button>
                ))}
                {!providerLoading && !visibleProviders.length && !providerError && <p className="provider-empty">Nenhum provedor encontrado. Use Buscar modelos para atualizar.</p>}
              </section>

              <section className="provider-detail-panel">
                <div className="provider-panel-title"><b><Cpu size={15} /> Modelos disponíveis</b><span>{visibleModels.length} modelos</span></div>
                {selectedProviderInfo ? <>
                  <div className="provider-detail-heading"><div><h3>{selectedProviderInfo.name}</h3><p>{selectedProviderInfo.connected ? "Sua conta já está conectada ao OpenCode." : "Conecte sua conta para habilitar os modelos."}</p></div><span className={`provider-state ${selectedProviderInfo.connected ? "connected" : ""}`}>{selectedProviderInfo.connected ? "Conectado" : "Não conectado"}</span></div>
                  {!selectedProviderInfo.connected && selectedProviderHasApiKey && <div className="provider-connect-box"><label>API key do {selectedProviderInfo.name}</label><div className="provider-key-row"><input type="password" value={providerApiKey} onChange={(e) => setProviderApiKey(e.target.value)} placeholder="Cole sua API key aqui" autoComplete="off"/><button className="btn-opencode-primary" disabled={providerSaving || !providerApiKey.trim()} onClick={connectProvider}>{providerSaving ? "Conectando..." : "Conectar"}</button></div><small>A credencial é enviada ao servidor OpenCode e salva no cofre de autenticação dele. Não é exibida na lista de modelos.</small></div>}
                  {!selectedProviderInfo.connected && !selectedProviderHasApiKey && selectedProviderHasOAuth && <div className="provider-connect-box"><b>Autenticação por conta (OAuth)</b><small>Este provedor exige autorização da conta. Conclua a conexão pelo fluxo oficial do OpenCode (/connect) no servidor vinculado; esta tela não pede sua senha nem simula uma conexão OAuth.</small></div>}
                  {(selectedProviderInfo.id === "opencode" || selectedProviderInfo.id === "opencode-go") && <div className="provider-connect-box"><b>Conta e créditos oficiais OpenCode</b><small>Para comprar créditos ou assinar o plano Go, abra o ambiente oficial do OpenCode. Depois, copie sua chave e conecte aqui.</small><div className="opencode-account-links"><a href="https://opencode.ai/console" target="_blank" rel="noreferrer">Abrir OpenCode Console <ExternalLink size={11}/></a><a href="https://opencode.ai/docs/console/go" target="_blank" rel="noreferrer">Conhecer OpenCode Go <ExternalLink size={11}/></a></div></div>}
                  {providerFeedback && <p className="provider-feedback">{providerFeedback}</p>}
                  <div className="provider-model-list">{visibleModels.slice(0, 120).map((item) => (
                    <div className={`provider-model-row ${model === `${selectedProviderInfo.id}/${item.id}` ? "selected" : ""}`} key={item.id}>
                      <div className="provider-model-info"><b>{item.name}</b><small>{item.id}{item.context ? ` · ${(item.context / 1000).toFixed(0)}k contexto` : ""}</small></div>
                      <div className="provider-model-meta">{item.free ? <span className="model-free"><CircleDollarSign size={12}/> Gratuito*</span> : <span className="model-paid">Pago / conforme provedor</span>}<button className="model-select-btn" onClick={() => { setModel(`${selectedProviderInfo.id}/${item.id}`); setSettings(false); }}>{model === `${selectedProviderInfo.id}/${item.id}` ? "Selecionado" : "Usar modelo"}</button></div>
                    </div>
                  ))}</div>
                  {visibleModels.length > 120 && <p className="provider-empty">Exibindo os primeiros 120 resultados. Refine a busca para localizar outros modelos.</p>}
                </> : <div className="provider-empty">Selecione um provedor para ver os modelos disponíveis.</div>}
              </section>
            </div>

            <div className="dark-notice-box neutral" style={{ marginTop: 14 }}>
              <ShieldCheck size={16} style={{ flexShrink: 0, color: "var(--accent-text)" }} />
              <div><b>Roteamento compartilhado:</b> quando 9Router estiver ativo, os usuários utilizam as contas e provedores configurados pela administração, sem inserir API própria. O roteador faz fallback/rotação conforme as cotas disponíveis; não cria tokens ilimitados. O uso continua sujeito aos termos, limites e disponibilidade de cada provedor.</div>
            </div>
            <div className="dark-modal-foot">
              <button className="header-btn" onClick={() => { setSettings(false); setProviderSearch(""); }}>Fechar</button>
              <button className="btn-opencode-primary" onClick={loadProviderCatalog}><RefreshCw size={14} /> Atualizar catálogo</button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

/**
 * Portão de acesso do CyberHuntLab. A bancada só é montada depois de uma sessão válida; sem
 * APP_ACCESS_TOKEN no servidor, a aplicação permanece bloqueada (fail-closed).
 */
export default function Home() {
  const [state, setState] = useState<"loading" | "unconfigured" | "login" | "ready">("loading");
  const [reason, setReason] = useState("");
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function checkSession() {
    try {
      const response = await fetch("/api/auth/session", { cache: "no-store" });
      const data = await response.json();
      if (!data.configured) { setReason(data.reason || ""); setState("unconfigured"); return; }
      setState(data.authenticated ? "ready" : "login");
    } catch {
      setError("Não foi possível contatar o servidor.");
      setState("login");
    }
  }

  useEffect(() => { void checkSession(); }, []);

  async function login(event: React.FormEvent) {
    event.preventDefault();
    if (!token.trim()) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token.trim() }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Falha no login.");
      setToken("");
      setState("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Falha no login.");
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).catch(() => undefined);
    setState("login");
  }

  if (state === "ready") return <Workbench onLogout={() => void logout()} />;

  return (
    <main className="shell" style={{ display: "grid", placeItems: "center", minHeight: "100vh", padding: 20 }}>
      <div className="dark-modal" style={{ position: "relative", maxWidth: 440, width: "100%" }}>
        <div className="dark-modal-head">
          <div>
            <h2><ShieldCheck size={18} style={{ color: "var(--accent-text)" }} /> CyberHuntLab</h2>
            <p>From Source Code to Security Evidence.</p>
          </div>
        </div>
        {state === "loading" && <div className="dark-modal-section"><span style={{ color: "var(--text-muted)", fontSize: 13 }}>Verificando sessão…</span></div>}
        {state === "unconfigured" && (
          <div className="dark-notice-box warning" style={{ display: "block" }}>
            <b>Acesso bloqueado até a configuração do servidor.</b>
            <p style={{ margin: "6px 0 0", fontSize: 12.5 }}>{reason} Defina <code>APP_ACCESS_TOKEN</code> com pelo menos 32 caracteres aleatórios (por exemplo, <code>openssl rand -base64 48</code>) e reinicie a aplicação.</p>
          </div>
        )}
        {state === "login" && (
          <form onSubmit={login}>
            <div className="dark-modal-section">
              <label>Token de acesso</label>
              <input type="password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="APP_ACCESS_TOKEN" autoComplete="current-password" autoFocus />
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>A sessão dura 12 horas e fica num cookie HttpOnly assinado; o token não é guardado no navegador.</span>
            </div>
            {error && <div className="dark-notice-box error" style={{ marginBottom: 12 }}><AlertCircle size={15} /><span>{error}</span></div>}
            <div className="dark-modal-foot">
              <button type="submit" className="btn-opencode-primary" disabled={busy || !token.trim()}>
                <Key size={13} /> {busy ? "Entrando…" : "Entrar"}
              </button>
            </div>
          </form>
        )}
      </div>
    </main>
  );
}
