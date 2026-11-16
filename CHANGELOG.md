# Changelog

## [1.1.0] — 2026-11-16

Primeira versão com a marca oficial **CyberHuntLab**. O foco é a segurança da própria plataforma, antes de qualquer módulo novo. OpenCode, 9Router, GitHub, workspace ZIP, engenharia reversa e skills continuam funcionando.

### Segurança (correções)

- **Crítico:** `/api/github/publish` não exigia autenticação e usava o `GITHUB_TOKEN` do servidor quando o visitante não enviava token. Qualquer pessoa com a URL podia criar repositórios e fazer push na conta da administração. Agora a rota exige sessão.
- **Crítico:** a autenticação dependia de `APP_ACCESS_TOKEN` estar definido e o frontend nunca enviava o token. Agora há login obrigatório com política fail-closed: sem token, a API responde 503. A sessão usa um cookie HttpOnly assinado, e o acesso é verificado em duas camadas (middleware e cada rota).
- **Alto:** SSRF via `customServerUrl` nas rotas de chat, workspace, catálogo de modelos e conexão de provedores. Agora o destino vem do servidor e é validado contra `OPENCODE_ALLOWED_HOSTS`.
- **Alto:** chaves Groq, GitHub e OpenCode ficavam no `localStorage` e trafegavam em cada requisição. Agora ficam num cofre AES-256-GCM em cookie HttpOnly, com migração automática e remoção do `localStorage`.
- **Alto:** o limite de 24 MB confiava no tamanho declarado no ZIP, que pode ser forjado (ZIP bomb). Agora a contagem é feita na descompactação real, com detecção de cabeçalho adulterado.
- **Médio:** symlinks, travessia de diretório e caminhos duplicados não eram tratados de forma uniforme. Agora rejeitam o ZIP inteiro em todas as rotas.
- **Médio:** `/api/github/verify` sem token devolvia os dados da conta GitHub do servidor. O fallback foi removido.
- A publicação no GitHub não envia mais `.env`, chaves privadas e arquivos de credenciais, mesmo que estejam no ZIP.

### Investigação

- O analisador foi extraído para `src/lib/audit/analyzer.ts`.
- Cada achado agora traz `ruleId`, `confidence`, `status`, linha, SHA-256 do arquivo, CWE (quando bem fundamentado) e `history`.
- O relatório inclui `integrity` (SHA-256 do ZIP e de cada arquivo lido) e contagens por confiança e por estado.
- O pesquisador pode mudar o estado de cada achado na interface, com nota opcional. O histórico vai junto no JSON exportado.
- Correção: antes, só a primeira regra encontrada em cada linha gerava achado. Agora regras de categorias diferentes geram achados separados, e segredos específicos não duplicam com a regra genérica.

### Novas rotas

- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/session`
- `GET|POST|DELETE /api/credentials`

### Testes

- `npm test`: 67 testes com `node:test`, sem dependências novas. Cobrem autenticação, CSRF, cofre, anti-SSRF, ZIP bomb com tamanho forjado, symlink, ZIP Slip, analisador, guardas estáticas das rotas e integração com os handlers reais.

### Verificação

- Os testes e a checagem de tipos dos módulos novos rodaram neste ambiente.
- `next build` **não** rodou aqui, porque não havia acesso à rede para instalar as dependências. Rode `npm install && npm run build && npm test` antes de implantar.

### Migração

1. Defina `APP_ACCESS_TOKEN` (mínimo de 32 caracteres; `openssl rand -base64 48`).
2. Se os usuários usam um servidor OpenCode próprio, inclua o host em `OPENCODE_ALLOWED_HOSTS`.
3. Na primeira carga após o login, as chaves antigas do navegador são migradas automaticamente. As que falharem na validação precisam ser informadas de novo.
