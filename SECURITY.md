# Segurança do CyberHuntLab

Este documento descreve os controles de segurança da própria plataforma (v1.1), as limitações conhecidas e como reportar problemas.

## Modelo de ameaça considerado

- Visitante anônimo que descobre a URL da implantação.
- Site malicioso aberto no mesmo navegador de um usuário logado (CSRF).
- ZIP malicioso enviado para análise: ZIP bomb, symlink, ZIP Slip, cabeçalhos adulterados.
- Tentativa de usar o backend como proxy para a rede interna (SSRF).
- Script injetado na página (XSS) tentando ler credenciais.

## Controles implementados

### Autenticação (fail-closed)

- `APP_ACCESS_TOKEN` é obrigatório e precisa ter pelo menos 32 caracteres. Sem ele, todo `/api/*` responde **503**, exceto `/api/health`, `/api/auth/login` e `/api/auth/session`.
- Login em `POST /api/auth/login`: comparação em tempo constante, limite de 8 tentativas a cada 15 min por IP e verificação de origem.
- A sessão é um cookie `chl_session` com `HttpOnly`, `Secure` (em produção) e `SameSite=Strict`. O conteúdo é `v1.<expiração>.<HMAC-SHA256>`, com validade de 12 h. **O token nunca vai para o cookie.**
- Há duas camadas: `src/middleware.ts` cobre `/api/:path*`, e cada handler chama `requireAuth`. O teste `tests/route-guards.test.ts` falha se alguma rota não pública deixar de chamar `requireAuth`.
- CSRF: requisições autenticadas por cookie que alteram estado (POST, PUT, PATCH, DELETE) precisam vir da mesma origem, verificada por `Origin`, `Sec-Fetch-Site` ou `Referer`. Clientes de API podem usar o cabeçalho `x-app-token`, que não sofre CSRF.
- **Implantação atrás de proxy reverso (nginx, Caddy):** repasse o host público (`proxy_set_header Host $host;` ou `X-Forwarded-Host`). Se o Next.js receber `Host: localhost:3000` enquanto o navegador envia `Origin: https://seu-dominio`, todos os POSTs serão recusados com 403. Na Vercel isso já vem configurado.

### Credenciais

- As chaves do usuário (Groq, GitHub, OpenAI, Gemini e servidor OpenCode privado) passam uma única vez por `POST /api/credentials` e são cifradas com **AES-256-GCM** num cookie `chl_vault` HttpOnly. A chave de cifra é derivada de `APP_ACCESS_TOKEN` (HMAC com rótulo de finalidade) e nunca sai do servidor.
- `GET /api/credentials` informa apenas o que está configurado, nunca os valores.
- As rotas ignoram credenciais enviadas no corpo ou em cabeçalhos (`userApiKeys`, `groqApiKey`, `x-github-token` etc.). Há teste estático para isso.
- Na primeira carga da v1.1, os segredos que versões anteriores guardavam no `localStorage` são migrados para o cofre e apagados do navegador.

### Anti-SSRF

- Um servidor OpenCode personalizado só é aceito se o host estiver em `OPENCODE_ALLOWED_HOSTS` ou for o host de `OPENCODE_SERVER_URL`.
- URLs com usuário e senha embutidos, query string, fragmento ou protocolo diferente de http(s) são recusadas.
- A senha do servidor padrão só é enviada à mesma origem de `OPENCODE_SERVER_URL`.
- As chamadas diretas a `/provider` e `/auth/:id` usam `redirect: "error"`.

### ZIPs enviados por usuários (`src/lib/security/safe-zip.ts`)

- Os limites são medidos nos bytes **realmente descompactados**, em stream, com orçamento por arquivo e global. O tamanho declarado no cabeçalho não é usado como garantia.
- Uma entrada cujo tamanho real difere do declarado é tratada como adulteração.
- Symlinks (`S_IFLNK`), caminhos absolutos, `..`, letras de unidade, caracteres de controle e caminhos duplicados (inclusive só por maiúsculas/minúsculas) **rejeitam o ZIP inteiro**.
- O nome original da entrada (`unsafeOriginalName`) é verificado. O JSZip ≥ 3.8 "limparia" o nome silenciosamente; aqui o arquivo é recusado.
- Nada é gravado em disco e nada é executado. O CRC não é verificado no carregamento, para não descompactar tudo de uma vez.
- Todas as rotas que recebem ZIP passam pelo leitor seguro: auditoria, workspace, engenharia reversa e publicação no GitHub. Arquivos `.env`, chaves privadas e credenciais nunca são publicados no GitHub.

## Limitações conhecidas (v1.1)

- **Um token, um operador.** Não há contas por usuário nem RBAC. Quem tem o token tem acesso total, e o servidor OpenCode e o 9Router são compartilhados. Não abra a implantação para usuários públicos.
- **Revogação de sessão é global.** As sessões não ficam guardadas no servidor. Para encerrar todas, troque `APP_ACCESS_TOKEN`. Isso também invalida os cofres de credenciais.
- **O cofre fica num cookie cifrado, não num banco de dados.** Quem roubar os dois cookies (sessão e cofre) consegue *usar* as credenciais através da aplicação até a sessão expirar, mas não consegue lê-las. Um banco com isolamento por usuário está previsto na fase de infraestrutura.
- **O limite de login é por instância.** Em serverless com várias instâncias, ele não é global. A solução prevista é Redis.
- **DNS.** A allowlist é por nome de host. Se um host autorizado apontar para um IP interno, essa é uma decisão da administração.
- **Publicação no GitHub:** quando o repositório não existe, ele é criado como **público** (comportamento herdado). Confira o nome antes de publicar.
- **O analisador é estático e baseado em padrões.** Não faz análise de fluxo de dados (taint) nem consulta CVE/OSV. Todo achado automático começa como `DETECTED` e não é uma vulnerabilidade confirmada.

## Como reportar uma vulnerabilidade

Abra um *security advisory* privado no repositório do GitHub (Security → Advisories → Report a vulnerability). Não abra issue pública. Inclua os passos para reproduzir, o impacto e a versão (`package.json`).
