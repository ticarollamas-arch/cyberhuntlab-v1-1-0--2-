import { NextRequest, NextResponse } from "next/server";
import { DEFAULT_ZIP_LIMITS, openSafeZip, ZipSecurityError, zipErrorStatus } from "@/lib/security/safe-zip";
import { requireAuth } from "@/lib/server/guard";

export const runtime = "nodejs";
export const maxDuration = 60;

// Sensitive file patterns to strictly sanitize
const SENSITIVE_PATTERNS = [
  /^\.env/i,
  /\.pem$/i,
  /\.key$/i,
  /id_rsa/i,
  /\.token/i,
  /credentials\.json/i,
  /\.npmrc/i,
  /\.pypirc/i,
  /node_modules\//i,
  /\.git\//i,
  /\.DS_Store/i,
];

function isSafeFile(name: string): boolean {
  return !SENSITIVE_PATTERNS.some((pattern) => pattern.test(name));
}

const SNIPPET_MAX_BYTES = 1024 * 1024;

export async function POST(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  try {
    const formData = await req.formData();
    const file = formData.get("archive");

    if (!(file instanceof File) || !file.name.toLowerCase().endsWith(".zip")) {
      return NextResponse.json(
        { error: "Por favor, envie um arquivo .zip válido." },
        { status: 400 }
      );
    }

    if (file.size > 3 * 1024 * 1024) {
      return NextResponse.json(
        { error: "Arquivo ZIP excede o limite de 3 MB desta implantação serverless." },
        { status: 413 }
      );
    }

    const zip = await openSafeZip(new Uint8Array(await file.arrayBuffer()), DEFAULT_ZIP_LIMITS);

    let packageJsonContent: Record<string, any> | null = null;
    let indexHtmlSnippet = "";
    let readmeSnippet = "";
    const structureTree: string[] = [];
    const componentsList: string[] = [];
    const routesList: string[] = [];
    let detectedFramework = "Vanilla / Não identificado";

    for (const entry of zip.entries) {
      const name = entry.path;
      if (!isSafeFile(name)) continue;

      structureTree.push(name);

      if (/components?\/.*\.(tsx|jsx|vue|svelte)$/i.test(name)) {
        componentsList.push(name.split("/").pop() || name);
      }
      if (/(pages|routes|app)\/.*\.(tsx|jsx|ts|js)$/i.test(name)) {
        routesList.push(name);
      }

      // Leituras passam pelo leitor seguro; erros de segurança do ZIP NÃO são silenciados.
      const wantsPackage = name.endsWith("package.json") && !packageJsonContent;
      const wantsHtml = name.endsWith("index.html") && !indexHtmlSnippet;
      const wantsReadme = /README\.md$/i.test(name) && !readmeSnippet;
      if (!(wantsPackage || wantsHtml || wantsReadme) || entry.declaredSize > SNIPPET_MAX_BYTES) continue;
      const text = await zip.readText(entry, SNIPPET_MAX_BYTES);
      if (text === null) continue;
      if (wantsPackage) {
        try { packageJsonContent = JSON.parse(text); } catch { /* package.json inválido */ }
      } else if (wantsHtml) {
        indexHtmlSnippet = text.slice(0, 1500);
      } else if (wantsReadme) {
        readmeSnippet = text.slice(0, 1500);
      }
    }

    if (structureTree.length === 0) {
      return NextResponse.json(
        { error: "O arquivo ZIP está vazio ou não contém arquivos de código válidos." },
        { status: 400 }
      );
    }

    // Detect Framework
    if (packageJsonContent) {
      const deps = {
        ...packageJsonContent.dependencies,
        ...packageJsonContent.devDependencies,
      };
      if (deps["next"]) detectedFramework = "Next.js (App / Pages Router)";
      else if (deps["@remix-run/react"]) detectedFramework = "Remix";
      else if (deps["vite"] && deps["react"]) detectedFramework = "React + Vite SPA";
      else if (deps["vue"]) detectedFramework = "Vue.js";
      else if (deps["@angular/core"]) detectedFramework = "Angular";
      else if (deps["express"]) detectedFramework = "Node.js + Express";
      else if (deps["react"]) detectedFramework = "React (CRA/Gatsby/Custom)";
    }

    return NextResponse.json({
      ok: true,
      fileName: file.name,
      fileSize: file.size,
      totalFiles: structureTree.length,
      detectedFramework,
      dependencies: packageJsonContent?.dependencies || {},
      devDependencies: packageJsonContent?.devDependencies || {},
      componentsCount: componentsList.length,
      routesCount: routesList.length,
      structureTree: structureTree.slice(0, 100),
      archiveSha256: zip.archiveSha256,
    });
  } catch (error) {
    if (error instanceof ZipSecurityError) {
      return NextResponse.json({ error: error.message, code: error.code }, { status: zipErrorStatus(error) });
    }
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Falha ao processar arquivo ZIP para engenharia reversa.",
      },
      { status: 500 }
    );
  }
}
