/**
 * Limitador de tentativas em memória (janela deslizante simples).
 *
 * Limitação conhecida: em ambientes serverless cada instância tem sua própria memória, então o
 * limite é por instância. Em VPS com processo único ele é global. Para produção multi-instância,
 * substituir por Redis (planejado na fase de infraestrutura).
 */
export class AttemptLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly maxAttempts: number;
  private readonly windowMs: number;
  constructor(maxAttempts: number, windowMs: number) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  /** Registra uma tentativa e informa se ainda está dentro do limite. */
  hit(key: string, now = Date.now()): { allowed: boolean; retryAfterSeconds: number } {
    const recent = (this.hits.get(key) || []).filter((time) => now - time < this.windowMs);
    if (recent.length >= this.maxAttempts) {
      this.hits.set(key, recent);
      return { allowed: false, retryAfterSeconds: Math.ceil((this.windowMs - (now - recent[0])) / 1000) };
    }
    recent.push(now);
    this.hits.set(key, recent);
    if (this.hits.size > 10_000) this.hits.delete(this.hits.keys().next().value as string);
    return { allowed: true, retryAfterSeconds: 0 };
  }

  reset(key: string) {
    this.hits.delete(key);
  }
}
