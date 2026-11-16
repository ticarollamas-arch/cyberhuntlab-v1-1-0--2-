# CyberHuntLab + OpenCode Workbench

> **CyberHuntLab — From Source Code to Security Evidence.** Plataforma integrada de engenharia de software e análise defensiva de segurança, com bancada OpenCode, roteamento de modelos de IA e laboratório de auditoria estática de projetos ZIP.

**Versão atual: 1.1.0** — fase de segurança da própria plataforma. Veja [CHANGELOG.md](CHANGELOG.md) e [SECURITY.md](SECURITY.md).

## Início rápido (v1.1)

```bash
npm install
cp .env.example .env.local
# Obrigatório: sem APP_ACCESS_TOKEN a API fica bloqueada (503).
echo "APP_ACCESS_TOKEN=$(openssl rand -base64 48)" >> .env.local
npm run dev        # http://localhost:3000 → tela de login pede o token
npm test           # 67 testes: autenticação, cofre, SSRF, ZIP bomb, symlink, analisador, rotas
```

### O que mudou na segurança

| Antes (≤ 1.0) | Agora (1.1) |
|---|---|
| Autenticação só existia se `APP_ACCESS_TOKEN` estivesse definido, e o frontend nunca enviava o token | Login obrigatório, sessão em cookie HttpOnly assinado (HMAC-SHA256, 12 h), middleware em todo `/api` + checagem em cada rota |
| `/api/github/publish` sem login usava o `GITHUB_TOKEN` do servidor | Publicação exige sessão; token do usuário vem do cofre do servidor |
| Chaves Groq/GitHub/OpenCode no `localStorage` e enviadas em cada requisição | Cofre AES-256-GCM em cookie HttpOnly; o navegador nunca vê os valores; migração automática e remoção do `localStorage` |
| `customServerUrl` do navegador → requisições do servidor para qualquer endereço (SSRF) | Servidor OpenCode personalizado só com host em `OPENCODE_ALLOWED_HOSTS` |
| Limite de ZIP baseado no tamanho declarado (forjável) | Bytes contados na descompactação real, orçamento global, detecção de cabeçalho adulterado |
| Symlinks e `..` não verificados em todas as rotas | Symlink, travessia, caminho absoluto e duplicatas rejeitam o ZIP inteiro em todas as rotas |
| Achados só com severidade | SHA-256 do ZIP e de cada arquivo, `confidence`, `status` (DETECTED → … → VALIDATED/FALSE_POSITIVE) e histórico de decisões do pesquisador |

O CyberHuntLab reúne a bancada de desenvolvimento OpenCode, integrações de IA/9Router e uma primeira camada de análise de segurança para projetos que o usuário possui ou está autorizado a avaliar. O módulo de segurança analisa arquivos e configurações sem executar o conteúdo do ZIP.

Repositório Oficial do OpenUI Code Code: [OpenUI Code Code](https://github.com/ticarollamas-arch/opencode-workspace-vercel)

---

## ⭐️ Créditos e Reconhecimento ao OpenCode

O **OpenUI Code Code** é uma interface visual projetada para operar em sinergia com o motor oficial de execução de código aberto **OpenCode**.

- **Projeto Open Source de Origem**: [OpenCode no GitHub](https://github.com/opencode-ai/opencode) (`github.com/OpenCode`)
- **SDK Oficial**: `@opencode-ai/sdk`
- **Reconhecimento**: Todos os créditos do motor de execução, arquitetura de agente e execução de código são atribuídos aos criadores e mantenedores do projeto open source **OpenCode**. O OpenUI Code Code atua exclusivamente como camada de interface web (Web UI) proporcionando uma experiência de desenvolvimento rica, visual e com suporte a chaves próprias de API.

---

## 🚀 Funcionalidades Principais do OpenUI Code Code

1. **Paleta Oficial OpenCode Dark**:
   - Design moderno em tema escuro baseado na identidade visual do OpenCode (painéis elegantes, tons profundos de grafite e detalhes em laranja/âmbar característicos).
   
2. **Navegação com Menu Hambúrguer (Drawer)**:
   - A lateral fixa foi substituída por um menu hambúrguer compacto e acessível, liberando 100% da área útil da tela para escrita de código e conversa com o executor.

3. **Página de Apresentação Integrada**:
   - Visão geral completa sobre o **OpenUI Code Code**, com atalhos rápidos e direcionamento aos créditos do **OpenCode**.

4. **Gerenciamento de Chaves de API no Painel (BYOK - Bring Your Own Key)**:
   - Os usuários podem inserir suas próprias chaves (Groq, OpenAI, Google Gemini, GitHub e servidor OpenCode privado) no painel "Minhas APIs".
   - Desde a v1.1 as chaves são enviadas uma única vez a `POST /api/credentials`, validadas (Groq e GitHub) e cifradas com AES-256-GCM num cookie HttpOnly. Elas não ficam no `localStorage` e o JavaScript da página não consegue lê-las. OpenAI e Gemini ficam guardadas para a fase de IA; as rotas atuais ainda não as consomem.

5. **Autenticação Direta no GitHub (PAT Simplificado)**:
   - Gere um token pessoal no GitHub e conecte sem cadastrar aplicações OAuth. O token é validado em `GET /user` e guardado somente no cofre do servidor.

6. **ZipToGit & Biblioteca de Skills**:
   - Envio de projetos compactados diretamente para repositórios do GitHub.
   - Detecção de habilidades modulares (`SKILL.md`) para orientar fluxos de trabalho especializados.

---

## 🧪 Testes

```bash
npm test
```

Os testes usam o executor nativo do Node (`node:test`) com remoção de tipos, sem dependências extras. Cobrem o núcleo de autenticação, o cofre, a política anti-SSRF, a extração segura de ZIP (bombs com tamanho forjado, symlinks, ZIP Slip), o analisador e os handlers reais das rotas (com uma implementação mínima de `next/server` em `tests/stubs`). Guardas estáticas impedem que uma rota nova seja criada sem `requireAuth` ou volte a aceitar credenciais e URLs do navegador.

## 🛠️ Como Executar Localmente

```bash
# 1. Instalar as dependências
npm install

# 2. Configurar variáveis de ambiente (APP_ACCESS_TOKEN é obrigatório desde a v1.1)
cp .env.example .env.local

# 3. Iniciar o servidor de desenvolvimento
npm run dev
```

Abra [http://localhost:3000](http://localhost:3000) no seu navegador para utilizar o **OpenUI Code Code**.

---

## 📄 Licença e Atribuição

Este projeto é disponibilizado sob os princípios de código aberto, respeitando as diretrizes do ecossistema [OpenCode](https://github.com/opencode-ai/opencode).


## Atualização visual e responsiva

A interface foi refinada para telas estreitas, largas e orientação vertical, com ajustes fluidos de espaçamento, tipografia e grades. A página de apresentação inclui agora links para GitHub e Instagram, uma vitrine animada de tecnologias e informações sobre a proposta do projeto e futuras demonstrações em vídeo. As etiquetas de categoria das skills passaram a usar estilo neutro, sem os antigos fundos verdes.


## Catálogo dinâmico de provedores e modelos

A Central de modelos consulta o endpoint oficial `GET /provider` do servidor OpenCode conectado. Assim, a lista acompanha os provedores e modelos que a versão instalada do OpenCode disponibiliza, em vez de depender de uma lista fixa no frontend.

- Busca por nome de provedor, nome de modelo ou ID.
- Exibe modelos gratuitos quando o catálogo do OpenCode informa preço de entrada zero; a disponibilidade e as condições podem mudar.
- Permite conectar provedores por API key usando `PUT /auth/:id` no servidor OpenCode. A credencial é enviada ao servidor e armazenada pelo mecanismo de autenticação do OpenCode, não no `localStorage` do navegador. No modo atual, o servidor OpenCode é compartilhado; portanto, não habilite conexão de provedores para usuários públicos sem implementar isolamento de credenciais por usuário (instância ou cofre separado).
- O modelo selecionado é enviado como `providerID/modelID` ao SDK.
- OAuth, autenticações com formulários especiais e provedores que exigem variáveis de ambiente ainda podem precisar do fluxo nativo `/connect` ou da configuração do servidor.

**Limites e cobrança:** o OpenUI Code Code não impõe cotas próprias de tokens. O uso continua sujeito aos créditos, planos, limites, rate limits e termos do provedor. Código aberto não significa APIs pagas ilimitadas.

### Referência de economia de tokens

A página de apresentação inclui [RTK — Rust Token Killer](https://github.com/rtk-ai/rtk), ferramenta open source que filtra e compacta saídas de comandos antes que cheguem ao contexto do modelo e oferece integração com OpenCode. É uma referência relevante de economia de tokens; não afirmamos que seja necessariamente o repositório citado pelo criador de conteúdo do Instagram. Para confirmar o projeto exato, precisamos do perfil ou vídeo original.

### Configuração do servidor OpenCode

Defina `OPENCODE_SERVER_URL` para o endereço do servidor OpenCode acessível pelo backend Next.js e, se necessário, `OPENCODE_SERVER_PASSWORD`. O servidor precisa estar ativo e protegido adequadamente. Não exponha a porta do OpenCode publicamente sem autenticação e regras de rede.

## Agente de projetos e entrega ZIP

O chat separa conversa comum de tarefas de projeto. Pedidos de criação/alteração de projeto e anexos ZIP são encaminhados a `POST /api/workspace`.

- **Criar do zero:** a IA retorna um manifesto estruturado de arquivos; o backend valida caminhos, monta a árvore com JSZip e entrega um ZIP para download.
- **Atualizar projeto:** o ZIP de origem é analisado; arquivos seguros e não modificados são preservados, enquanto os arquivos retornados pela IA substituem ou complementam a árvore. A conversa mantém o último ZIP gerado durante a sessão do navegador para revisões subsequentes.
- **README:** a geração solicita documentação de instalação, execução e configuração. Se nenhum README for produzido, o servidor inclui um README básico.
- **Entrega compacta:** a conversa exibe um resumo e um botão de download, não despeja o código integral no histórico.
- **Fila de tarefas:** novas instruções enviadas durante uma execução são enfileiradas e processadas em sequência; não abortam a tarefa atual.
- **Engenharia reversa:** a análise técnica do ZIP é seguida pelo envio do próprio arquivo ao agente de projetos. A recriação deve ser autorizada e independente; não copia código proprietário nem remove marcas d'água para ocultar autoria.
- **Segurança:** `.env`, chaves, credenciais, `.git`, `node_modules` e artefatos de build são excluídos do contexto/ZIP. `.env.example` é permitido.

### Provedores do agente

Quando `OPENCODE_SERVER_URL` (e opcionalmente `OPENCODE_SERVER_PASSWORD`) estiver configurado, a geração usa a sessão e o modelo selecionado no servidor OpenCode. Sem servidor OpenCode, a geração utiliza Groq e requer `GROQ_API_KEY` no ambiente ou uma chave informada pelo usuário. Modelos/provedores selecionados fora da Groq exigem o servidor OpenCode conectado.

### Limites da implantação Vercel

Esta versão serverless limita ZIP de entrada e saída a 3 MB para respeitar limites de payload da plataforma. A função tem duração máxima configurada de 60 segundos. Projetos maiores ou execuções longas precisam de executor persistente em VPS e armazenamento de artefatos (por exemplo, S3 compatível). O backend não afirma que executou `npm install`, build ou testes; o resultado informa explicitamente quando essas verificações não foram executadas.

## 9Router — catálogo sincronizado, Start e fallback automático

O OpenUI Code Code integra o [9Router](https://github.com/decolua/9router) como gateway compartilhado OpenAI-compatible. A Central de modelos possui **Carregar modelos**, **Sincronizar 9Router** e **Start 9Router**. Ao iniciar, o backend verifica `/health`, sincroniza `/v1/models` e seleciona o combo padrão definido pela administração. As mensagens do chat e a geração/atualização de projetos ZIP são encaminhadas para `/v1/chat/completions`; o 9Router executa a estratégia de fallback/rotação configurada nesse combo.

### Configuração obrigatória no servidor

1. Instale e execute o 9Router no mesmo VPS/rede privada do Next.js (porta padrão `20128`). Consulte a documentação oficial do projeto para instalação e atualização.
2. No painel do 9Router, conecte os provedores/contas que a administração disponibilizará aos usuários. Use os fluxos OAuth oficiais ou credenciais autorizadas. Crie um combo em **Dashboard → Combos**, por exemplo `openui-coding`, com os modelos em ordem de prioridade e estratégia `Fallback` ou `Round Robin`. O nome precisa aparecer em `GET /v1/models`.
3. Crie uma chave de acesso do próprio 9Router para o OpenUI Code Code. Mantenha o serviço em `127.0.0.1` ou rede privada; não exponha a porta de administração diretamente à internet.
4. Configure no ambiente server-side do Next.js/Vercel/VPS:

```env
NINEROUTER_BASE_URL=http://127.0.0.1:20128
NINEROUTER_API_KEY=sua-chave-de-acesso-do-9router
NINEROUTER_DEFAULT_COMBO=openui-coding
```

Se Next.js e 9Router estiverem em containers separados, use o hostname interno do serviço Docker, não `127.0.0.1`. **Se a interface estiver na Vercel e o 9Router no VPS**, `127.0.0.1` aponta para a própria infraestrutura da Vercel, não para seu VPS: configure um subdomínio HTTPS do VPS e use-o em `NINEROUTER_BASE_URL` (por exemplo, `https://router-api.cyberhuntlab.com.br`). Há um exemplo em `deploy/nginx-9router-api.conf.example` que publica somente `/v1/*` e `/health`, bloqueando o dashboard e as rotas administrativas. Mantenha o 9Router escutando em `127.0.0.1:20128` e proteja a API com a chave server-side.

### Como o usuário utiliza

- Abre **Configurações → Central de modelos**.
- Clica em **Carregar modelos** ou **Sincronizar 9Router**.
- Clica em **Start 9Router**; o app verifica o serviço e seleciona o combo `NINEROUTER_DEFAULT_COMBO`, que faz o fallback/rotação configurado.
- Não precisa inserir a própria API key: o backend usa a chave do roteador, guardada somente nas variáveis de ambiente do servidor.

**Importante:** isso é uma integração compartilhada administrada pelo dono do serviço. As contas/provedores do 9Router precisam ser conectados e mantidos pela administração. A rotação pode continuar em outro provedor quando houver cota disponível, mas não cria tokens ilimitados nem garante disponibilidade permanente. A elegibilidade, cotas, autenticação, termos e cobrança continuam sendo definidos por cada provedor. Nunca compartilhe uma chave administrativa do 9Router no navegador.


## CyberHuntLab — Auditoria estática de ZIP

A aba **CyberHuntLab** recebe ZIPs de projetos e faz inspeção estática de arquivos de texto, com indicadores para: possíveis segredos expostos, validação TLS desativada, execução dinâmica, CORS permissivo, debug, Docker, Kubernetes, Terraform, dependências declaradas e presença de configuração Vercel. O relatório pode ser exportado em JSON ou enviado ao modelo selecionado no chat para triagem assistida por IA.

### Modelo de achado (v1.1)

Cada achado traz `ruleId`, `severity`, **`confidence`** (precisão da regra: alta = padrão específico; baixa = heurística que exige leitura do contexto), **`status`**, arquivo, linha, **SHA-256 do arquivo**, CWE quando bem fundamentado e `history`. O relatório inclui `integrity.archiveSha256` e o hash de cada arquivo lido.

Fluxo de estados: `DETECTED → ANALYZING → EVIDENCE_FOUND → VALIDATED | UNCONFIRMED | FALSE_POSITIVE`. O analisador cria somente `DETECTED`; as demais transições são decisões do pesquisador na interface, registradas com data e nota no histórico e preservadas no JSON exportado.

### Limites e uso responsável

- Aceita ZIP de até 3 MB na implantação Vercel, até 1.500 entradas e 24 MB **realmente** descompactados (contagem em stream, não pelo cabeçalho). ZIPs com symlink, travessia de diretório ou tamanho adulterado são recusados por inteiro.
- O analisador não executa código, scripts, containers ou manifests e não testa endpoints.
- Não consulta automaticamente CVE/OSV; a presença de uma dependência não significa que ela seja vulnerável.
- Não acessa uma conta Vercel nem um cluster Kubernetes remoto: somente avalia arquivos incluídos no ZIP.
- Achados são indicadores para triagem, sujeitos a falsos positivos e validação humana.
- Use apenas em projetos próprios ou com autorização explícita.

### Evolução recomendada

Para ampliar a cobertura, conecte um executor isolado na VPS e integre ferramentas especializadas como Trivy, Semgrep, OSV-Scanner e Checkov, mantendo limites de recursos, isolamento de rede, logs e aprovação humana.
