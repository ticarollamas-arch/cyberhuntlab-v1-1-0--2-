// Substituto do @opencode-ai/sdk nos testes: registra o baseUrl usado e falha sem rede.
export const calls: string[] = [];
export function createOpencodeClient(options: { baseUrl: string }) {
  calls.push(options.baseUrl);
  const fail = async () => { throw new Error(`stub OpenCode: sem rede (${options.baseUrl})`); };
  return { session: { create: fail, prompt: fail, abort: fail, delete: fail } };
}
