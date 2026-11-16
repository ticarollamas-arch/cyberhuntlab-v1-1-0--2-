// Resolve imports do código-fonte nos testes (node --test com type stripping):
//  - "@/x"  -> src/x
//  - imports relativos sem extensão -> tenta .ts, .tsx e /index.ts
// Assim o código de produção mantém o estilo de imports do Next.js.
import { existsSync, statSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function candidates(base) {
  return [base, `${base}.ts`, `${base}.tsx`, path.join(base, "index.ts")];
}

const STUBS = {
  "next/server": path.join(root, "tests", "stubs", "next-server.ts"),
  "@opencode-ai/sdk": path.join(root, "tests", "stubs", "opencode-sdk.ts"),
};

export async function resolve(specifier, context, next) {
  if (STUBS[specifier]) return next(pathToFileURL(STUBS[specifier]).href, context);
  let base = null;
  if (specifier.startsWith("@/")) base = path.join(root, "src", specifier.slice(2));
  else if ((specifier.startsWith("./") || specifier.startsWith("../")) && context.parentURL?.startsWith("file:")) {
    base = path.resolve(path.dirname(fileURLToPath(context.parentURL)), specifier);
  }
  if (base) {
    for (const file of candidates(base)) {
      if (existsSync(file) && statSync(file).isFile()) return next(pathToFileURL(file).href, context);
    }
  }
  return next(specifier, context);
}
