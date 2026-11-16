import { NextRequest, NextResponse } from "next/server";
import { analyzeArchive } from "@/lib/audit/analyzer";
import { DEFAULT_ZIP_LIMITS, openSafeZip, ZipSecurityError, zipErrorStatus } from "@/lib/security/safe-zip";
import { requireAuth } from "@/lib/server/guard";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  const denied = await requireAuth(req);
  if (denied) return denied;
  try {
    const file = (await req.formData()).get("archive");
    if (!(file instanceof File) || !file.name.toLowerCase().endsWith(".zip")) {
      return NextResponse.json({ error: "Envie um arquivo .zip válido." }, { status: 400 });
    }
    if (file.size <= 0 || file.size > DEFAULT_ZIP_LIMITS.maxArchiveBytes) {
      return NextResponse.json({ error: "ZIP vazio ou maior que 3 MB nesta implantação Vercel." }, { status: 413 });
    }
    const zip = await openSafeZip(new Uint8Array(await file.arrayBuffer()), DEFAULT_ZIP_LIMITS);
    const report = await analyzeArchive(zip, file.name);
    return NextResponse.json(report, { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    if (error instanceof ZipSecurityError) {
      return NextResponse.json({ error: `ZIP recusado: ${error.message}`, code: error.code, path: error.path }, { status: zipErrorStatus(error) });
    }
    return NextResponse.json({ error: error instanceof Error ? error.message : "Falha na análise de segurança do ZIP." }, { status: 500 });
  }
}
