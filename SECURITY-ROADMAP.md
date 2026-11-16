# CyberHuntLab — arquitetura e evolução

## Ordem de desenvolvimento

1. **Segurança da plataforma (v1.1 — concluída):** autenticação obrigatória, credenciais no servidor, ZIP seguro, anti-SSRF.
2. **Investigação (v1.1 — base concluída):** SHA-256, `confidence`, `status` e histórico por achado.
3. **Relatórios:** exportação JSON (feito), SARIF e Markdown.
4. **IA:** chat integrado para investigar achados reais, explicar evidências e propor correções.
5. **Infraestrutura:** FastAPI e workers isolados somente quando houver necessidade técnica comprovada.

## Produto integrado nesta versão

- **CyberHuntLab:** auditoria estática inicial de projetos ZIP.
- **OpenCode Workbench:** chat de engenharia, workspace ZIP, engenharia reversa autorizada e integração com GitHub.
- **AI Gateway:** catálogo de modelos, Groq, OpenCode e 9Router, conforme credenciais configuradas no servidor.
- **Skills:** catálogo de habilidades para apoiar tarefas de engenharia.

## Fluxo da auditoria ZIP

1. O usuário seleciona um ZIP de um projeto próprio ou autorizado.
2. A API valida extensão, tamanho, quantidade de entradas e limite de conteúdo descompactado.
3. Arquivos sensíveis e diretórios de dependências/build são ignorados.
4. O analisador inspeciona arquivos de texto e configurações sem executar scripts, containers ou binários.
5. Achados são apresentados com severidade indicativa, arquivo, evidência e recomendação.
6. O usuário pode exportar JSON ou enviar o relatório ao modelo selecionado para triagem assistida.

## Limites desta entrega

- ZIP até 3 MB compactados na implantação Vercel.
- Até 1.500 entradas e 24 MB descompactados.
- Cobertura baseada em padrões estáticos; não equivale a pentest, SAST completo ou auditoria de cloud ao vivo.
- Sem consulta automática a CVE/OSV nesta versão.
- A IA recebe o relatório e pode ajudar a interpretar, mas não deve transformar suspeitas em vulnerabilidades confirmadas.

## Próxima arquitetura recomendada para VPS

```text
Next.js / Vercel UI
        |
        v
API autenticada + fila de trabalhos
        |
        v
Executor isolado na VPS (Docker rootless)
        |
        +--> Trivy (filesystem, image, IaC)
        +--> Semgrep (SAST)
        +--> OSV-Scanner (dependências)
        +--> Checkov (Terraform/Kubernetes/IaC)
        +--> Gitleaks (segredos)
        |
        v
Normalização SARIF/JSON -> deduplicação -> evidências
        |
        v
IA para triagem, explicação e plano de correção
        |
        v
Relatório HTML/PDF/JSON + histórico auditável
```

## Controles obrigatórios para o executor

- Rodar como usuário sem privilégios, com filesystem temporário e limites de CPU/RAM/tempo.
- Sem acesso à rede por padrão; permitir apenas destinos explicitamente necessários.
- Não executar `install`, scripts de build ou código do ZIP por padrão.
- Impedir escape de diretório, symlinks perigosos, arquivos especiais e arquivos compactados-bomba.
- Aplicar autenticação, cotas por usuário, logs de auditoria e retenção limitada.
- Nunca enviar segredos encontrados para o modelo; mascarar valores antes de gerar o contexto da IA.
- Exigir autorização e escopo documentados para qualquer teste dinâmico ou remoto.

## Sobre Kubernetes e Vercel

Um ZIP de manifests Kubernetes permite revisar configurações declaradas no pacote. Não revela a configuração efetiva do cluster, admission controllers, RBAC aplicado, secrets ativos ou estado dos pods. Para isso, será necessário um conector Kubernetes com credenciais de leitura mínima e autorização do operador.

Um ZIP de projeto Vercel permite revisar código e `vercel.json`. Não revela Environment Variables, deployments, domains, access controls, logs ou configurações da conta. Para auditar esses elementos será necessário integrar APIs oficiais da Vercel com autorização explícita.
