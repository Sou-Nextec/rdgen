# rdgen Nextec (fork de bryangerlach/rdgen)

Gerador de clientes RustDesk da Nextec. O código é o do [rdgen](https://github.com/bryangerlach/rdgen) com mudanças pequenas,
quase todas concentradas em `rdgenerator/nextec.py`. Visão geral do projeto, servidores e como continuar: no repositório
`Sou-Nextec/rustdesk-api-web`, arquivo `nextec/CONTINUAR.md`. Passo a passo de implantação na stack: `nextec/deploy/GERADOR.md`.

## Como funciona

O rdgen **não compila nada**. O formulário grava o pedido, cifra os dados do build num pacote (`secrets_<uuid>.zip`, AES com
`ZIP_PASSWORD`) e dispara um workflow do GitHub Actions neste mesmo repositório (`generator-windows.yml`, `generator-linux.yml`).
O runner baixa o pacote, compila (30 a 45 min), devolve o executável para o servidor (`save_custom_client`) e o usuário baixa
pelo formulário. Os workflows precisam ficar neste repositório; a imagem do gerador roda na stack do servidor.

## O que a Nextec mudou

| Mudança | Onde |
| --- | --- |
| Caminho `/gerador` no mesmo domínio do painel (`URL_PREFIX`) | `rdgen/wsgi.py` |
| Servidor, porta, chave pública, API, links e empresa preenchidos e travados (`NX_*`), forçados também no servidor | `rdgenerator/nextec.py`, `forms.py`, `views.py` |
| Ícone e logo padrão da Nextec | `nextec/branding/`, `rdgenerator/nextec.py` |
| Só Windows 64 e Linux no formulário | `forms.py`, `templates/generator.html` |
| URLs relativas (funcionam sob prefixo) e URL de retorno com prefixo | `templates/*.html`, `views.py`, `api_views.py` |
| Nome do app só `[A-Za-z0-9-]`; porta do servidor de ID recusa 21117 a 21119 | `forms.py` |
| Rotas chamadas pelo GitHub endurecidas: token por build, uuid inteiro, nomes exatos, limite de 600 MB | `views.py` (`build_token`, `save_custom_client`, `cleanup_secrets`, `get_zip`) |
| `SECRET_KEY` automática (arquivo no volume) e aviso de configuração incompleta (503) | `rdgen/settings.py`, `rdgenerator/nextec.py`, `templates/config_problem.html` |
| Banco SQLite em volume (`DB_PATH`), `migrate` na subida, usuário não root, 2 workers | `Dockerfile`, `rdgen/settings.py`, `gunicorn.conf.py` |
| Imagem `ghcr.io/sou-nextec/rdgen-nextec` com teste de fumaça | `.github/workflows/nextec-imagem.yml` |

Após uma publicação bem-sucedida em `master`, o workflow chama o webhook do Portainer para refazer a stack e buscar a imagem `latest`. Configure `PORTAINER_WEBHOOK_URL` como segredo de Actions neste repositório (ou como segredo da organização com acesso ao repositório). Sem esse segredo, a imagem é publicada, mas a stack não é acionada.

## Variáveis de ambiente

Originais do rdgen: `GHUSER`, `GHBEARER`, `GHBRANCH`, `REPONAME`, `GENURL`, `ZIP_PASSWORD`, `SH_SECRET`, `SECRET_KEY`, `PROTOCOL`.
Sem token, usuário, `ZIP_PASSWORD` ou `SH_SECRET` (ou com os valores padrão `insecure` e `secret`), a página mostra o que falta.

Da Nextec:

| Variável | Para quê |
| --- | --- |
| `URL_PREFIX` | Caminho em que o gerador responde (ex.: `/gerador`) |
| `DB_PATH` | Arquivo do banco (padrão da imagem: `/opt/rdgen/data/db.sqlite3`) |
| `NX_SERVER_HOST`, `NX_SERVER_PORT`, `NX_API_SERVER` | Servidor de ID (porta vazia = 21116) e URL do painel |
| `NX_KEY` ou `NX_KEY_FILE` | Chave pública do servidor (texto, ou caminho do `id_ed25519.pub` montado só leitura) |
| `NX_ENROLL_KEY` | **Override opcional** da chave de inscrição global (`nx1.<época>.<assinatura>`). Normalmente não é necessário: o gerador busca a chave vigente no painel a cada build. Só é usada quando a busca falha. Nunca vai ao banco, a modelos nem a logs |
| `NX_PANEL_INTERNAL_URL` | Painel na rede interna da stack, de onde a chave é buscada (padrão `http://rustdesk:21114`). Vazio desliga a busca automática |
| `NX_URL_LINK`, `NX_DOWNLOAD_LINK`, `NX_COMPANY`, `NX_APP_NAME` | Links, empresa e nome padrão do app |
| `NX_LOCK_SERVER` | `1` (padrão) trava os campos acima, no formulário e no servidor |
| `NX_ICON_FILE`, `NX_LOGO_FILE` | Imagens padrão (PNG quadrado) quando nenhuma é enviada |
| `NX_ALLOWED_EMAILS` | E-mails autorizados a gerar (vírgula ou espaço). Vazio = quem passa pelo Access. Veja "Quem pode gerar" |
| `NX_BRANDING_DIR` | Diretório persistente das imagens gerenciadas (padrão: `/opt/rdgen/data/branding`, dentro do volume `rdgen-db`) |
| `WEB_CONCURRENCY` | Processos do gunicorn (padrão 2) |

Sem `NX_SERVER_HOST` o gerador se comporta como o original.

## Inscrição global das máquinas

A cada build o gerador busca a chave vigente no painel (`GET {NX_PANEL_INTERNAL_URL}/api/nextec/gen/enroll-key`, timeout de 3 s, cabeçalho
`X-Nextec-Gen-Secret` com o `SH_SECRET`, que é o mesmo `NX_RDGEN_SHARED_SECRET` da API; sem redirecionamento; nem a chave nem o segredo vão a log).
Se a busca falhar, usa `NX_ENROLL_KEY` do ambiente. Com uma chave válida, coloca `enroll_key` e `enroll_panel` (URL de `NX_API_SERVER`) no `secrets_<uuid>.zip` cifrado.
Exige o patch `0033-gen-enroll-key.patch` na API do painel (painel 2.11.8 ou mais novo).
O workflow (mascarados no Actions) grava `{"v":1,"painel":"<URL>","chave":"<chave>"}` e o instala assim:

- MSI e EXE (que embute o MSI): `inscricao.json` ao lado dos scripts, componente `Nextec.Enrollment`, sem alterar os hashes dos scripts.
- DEB (somente pacote com agente, `nx_agent` ligado, que leva o coordenador): `/usr/lib/nextec-connect/inscricao.json`, `root:root` 0600, ao lado de
  `coordenador-agente-nextec-linux.py`, que é a fonte que o coordenador lê (e depois copia para `/var/lib/nextec-connect`).
  Instalado por `nextec/atualizacao/inscricao-linux.sh`.

Sem chave (painel inacessível e sem `NX_ENROLL_KEY`), o build segue e o instalador sai sem o arquivo, com aviso na tela e na saída do build. A chave é o segredo que autoriza
inscrição: rotacione-a no painel se um instalador vazar.

Requisitos na stack:

- `SH_SECRET` do gerador igual ao `NX_RDGEN_SHARED_SECRET` da API (a stack já usa `GERADOR_SH_SECRET` nos dois) e os dois serviços na mesma rede
  Docker (`rustdesk:21114`). `NX_ENROLL_KEY` fica só como reserva.
- `NX_API_SERVER`: a URL HTTPS do painel **aceita pelo agente** (hoje `https://painel-remoto.nex.tec.br`; o agente recusa
  qualquer outro valor com `invalid_panel`, então um instalador com outra URL não se inscreve).
- **Girar a chave no painel NÃO atualiza instaladores já gerados ou instalados**: eles guardam a chave antiga e passam a receber 401
  (autorização manual). Depois de girar, basta gerar instaladores novos: o gerador busca a chave nova sozinho.

Os scripts empacotados (`Provisionar-Agente-Nextec.ps1`, `Coordenar-Agente-Nextec.ps1`, `Agente-Senha-Nextec.ps1`,
`coordenador-agente-nextec-linux.py`) são cópias versionadas de `Sou-Nextec/rustdesk-api-web` (commit e hash em
`nextec/atualizacao/Agente-Senha-Nextec.provenance.txt`); atualize-as por cópia do painel, nunca à mão aqui.

Testes da inscrição empacotada: `rdgenerator/test_enrollment.py` (gerador), `.github/scripts/test-msi-build.ps1` e
`nextec/atualizacao/test_self_enroll_installed.ps1` (Provisionar empacotado/instalado lê o `inscricao.json` e faz o POST
self-enroll contra um painel falso local: 200 pendente, 404 retry, 401/409 manual, 403 parada) e
`nextec/atualizacao/test_inscricao_deb_linux.py` (caminho e consumo no DEB).

## Nome do app livre e agente por flag

O nome do app pode ser qualquer um (`XPTO`, `Client-Nextec-Connect`, `Nextec-Connect`...). Nada decide por comparação de nome.

- **Flag `nx_agent`** (`true`/`false`), campo do formulário/API que viaja no `secrets_<uuid>.zip` e vira `env.nx_agent` nos workflows.
  Ligado por padrão (cliente de acesso). Fica desligado só para o app de suporte avulso: `nx_agent=false` explícito, ou
  `installation=installationN` (app que não instala) quando o flag não vem. Regra única em `rdgenerator/nextec.py::agent_enabled`.
- Com o flag ligado o pacote leva Coordenar, Provisionar, Agente-Senha, atualizador e as ações de registro (MSI: `build-msi.ps1
  -IncludeAgent`; EXE: embrulho do MSI, só gerado com o agente; DEB: `empacotar-deb-atualizador.sh`). Desligado, sai só o cliente
  (sem agente, sem atualizador, sem `inscricao.json`).
- **Marcador de instalação** independente de nome, gravado junto dos scripts: `nextec-marker.json` com `{"v":1,"app","upgrade_code"}`.
  No MSI também `HKLM\SOFTWARE\Nextec\Agente` com `InstallDir` e `AppName` (componentes `Nextec.AgentMarker`/`Nextec.AgentRegistry`).
  No DEB o marcador fica em `/usr/lib/nextec-connect/nextec-marker.json` e `upgrade_code` é o nome do pacote.
  Qualquer script novo deve localizar a instalação por esse marcador/registro, nunca pelo nome do executável.
- Os componentes Windows empacotados que o painel versiona (`*.ps1`) seguem sincronizados do painel; o marcador é o ponto de apoio
  para que eles deixem de depender do nome.

## Painel configurável (sem domínio fixo)

O MSI e os scripts Linux não trazem host embutido. O painel vem do build:

- MSI: o atualizador recebe `-UrlBase <painel>/api/nextec/update`, montado no build a partir de `enroll_panel` (ou `apiServer`).
- Linux: `atualizador-linux.py`, `coordenador-agente-nextec-linux.py` e `agente-senha-linux.py` leem `painel` do `inscricao.json`
  instalado (`/usr/lib/nextec-connect`, depois `/var/lib/nextec-connect`), só se o arquivo for regular, do root (ou do usuário que roda)
  e sem escrita para grupo/outros.
- Trava de segurança mantida: somente `https` (porta 443 ou omitida), sem usuário, caminho, query ou fragmento; o host de qualquer
  redirecionamento ou resposta precisa ser o do painel configurado. Valor vindo da rede ou de variável de ambiente nunca é aceito.
  Sem painel configurado os componentes não agem (`panel_not_configured` / mensagem do atualizador).

Testes: `python manage.py test rdgenerator` (`test_agent_flag.py`), `.github/scripts/test-msi-build.ps1` (casos `XPTO`,
`Client-Nextec-Connect`, `Nextec-Connect` com agente e suporte sem agente), `.github/scripts/test-setup-exe.ps1` e
`nextec/atualizacao/test_painel_configuravel_linux.py` (Linux e CI do DEB).

## Versão e imagens

`rdgenerator/VERSION` guarda a versão da experiência do gerador, atualmente `2.3.0`. Ao alterar layout ou recursos próprios,
atualize esse arquivo e acrescente uma entrada em `nextec/CHANGELOG.md`. Essa versão é separada da versão-base RustDesk usada
no build e da versão do produto publicada na tela de atualizações do painel.

Na aba **Identidade visual**, ícone, logo e tela de privacidade aceitam PNG e ficam no volume de dados existente do
gerador para as próximas gerações. A personalização do bitmap MSI depende de isolar o build Windows dos segredos de
upload; consulte `nextec/ROADMAP.md`.

**Imagens padrão do MSI:** `nextec/branding/WixUIDialogBmp.bmp` (493 × 312) e `WixUIBannerBmp.bmp` (493 × 58),
BMP 24 bits, geradas por `python nextec/scripts/gerar_imagens_msi.py` a partir de `nextec/branding/logo.png`.
Sem upload na aba Identidade visual, `get_artwork/msi_dialog` e `msi_banner` servem essas imagens e todo MSI sai com elas.
Um upload continua tendo prioridade; remover o upload volta ao padrão Nextec.
Só entram em produção com Pull and redeploy do gerador.

Os **modelos de configuração** ficam no mesmo banco persistente do gerador, separados pelo e-mail autenticado no
Cloudflare Access. Senha permanente, chave pública, imagens e ajustes manuais não são armazenados nesses modelos.
Também é possível exportar ou importar JSON; confira os campos após importar. A geração continua sendo uma plataforma
por vez. Para distribuir um MSI, a tela de resultado abre a área de atualizações do painel; a publicação é manual.
Os EXE/MSI gerados ainda não instalam a tarefa de atualização automática (veja `nextec/ROADMAP.md`).

## Segredos do repositório (GitHub > Settings > Secrets and variables > Actions)

- `GENURL`: endereço público do gerador, com o prefixo, sem barra final (`https://painel-remoto.nex.tec.br/gerador`).
- `ZIP_PASSWORD`: igual ao `ZIP_PASSWORD` do servidor (no Portainer: `GERADOR_ZIP_SENHA`). Use um valor longo e aleatório.

## Quem pode gerar

Só administradores e pessoas autorizadas. São duas camadas:

1. **Cloudflare Access** (Entra): quem entra em `/gerador`. Ajuste a política para o grupo certo.
2. **Lista do gerador** (`NX_ALLOWED_EMAILS`, no Portainer: `GERADOR_EMAILS_AUTORIZADOS`): o middleware
   `rdgenerator/middleware.py` compara o e-mail que o Access autenticou (`Cf-Access-Authenticated-User-Email`) com a lista e
   mostra "Você não está autorizado a gerar clientes" (403) a quem não está. Sem cabeçalho (acesso direto, sem Access) também
   é recusado. As rotas do GitHub (`updategh`, `cleanzip`, `save_custom_client`, `get_png`, `get_zip`) e a verificação de saúde
   local não passam por essa lista.

O cabeçalho só é confiável porque o contêiner não é publicado: o único caminho até ele é o túnel, que passa pelo Access.

## Segurança das rotas liberadas no Access

O Cloudflare Access protege o formulário com login, mas o GitHub Actions não faz login. Por isso só estas rotas ficam em Bypass:
`cleanzip`, `save_custom_client`, `get_png` e `get_zip`. Cada uma se protege sozinha (token por build dentro do pacote cifrado,
uuid completo, nome exato `secrets_<uuid>.zip`, limite de tamanho). O `updategh` não é usado (o status vem da API do GitHub) e
fica fora do Bypass. Evite "senha permanente" no formulário: ela vai dentro do pacote cifrado.

## Desenvolver e testar

```bash
docker build -t rdgen-nextec:teste .
docker run --rm rdgen-nextec:teste python manage.py test rdgenerator
docker run -d -p 8000:8000 -e URL_PREFIX=/gerador -e GHUSER=t -e GHBEARER=t -e ZIP_PASSWORD=senha-forte -e SH_SECRET=outra-forte \
  -e NX_SERVER_HOST=remoto.exemplo -e NX_API_SERVER=https://painel.exemplo -e NX_KEY=CHAVE= rdgen-nextec:teste
# http://localhost:8000/gerador/
```

Para ver o erro real de um 500 num servidor (o log do gunicorn não mostra):

```bash
docker exec rdgen python -c "import os,django; os.environ['DJANGO_SETTINGS_MODULE']='rdgen.settings'; django.setup(); from django.test import Client; print(Client(raise_request_exception=True).get('/').status_code)"
```

## Sincronizar com o upstream

```bash
git remote add upstream https://github.com/bryangerlach/rdgen.git   # só na primeira vez
git fetch upstream
git checkout -b sync-upstream
git merge upstream/master
```

Conflitos prováveis: `rdgenerator/views.py`, `forms.py` e `templates/generator.html`. Depois do merge, rode os testes e o teste
de fumaça (o CI faz). Os workflows `generator-*.yml` não foram alterados; se o upstream mudar o formato do `secrets.json`, confira
que o campo `token` continua sendo exportado como `env.token` (a ação `decrypt-secrets` valida os campos conhecidos antes
de exportá-los).

## Correções de 10/10/2026

Preparadas para PR; merge condicionado à CI. A API `POST /api/generate` exige `Authorization: Bearer <SH_SECRET>`, além das
restrições do Cloudflare Access. JSON precisa ser objeto, strings e booleanos têm tipos verificados, e escolhas,
nome do app e porta passam pelas mesmas regras do formulário. Plataformas disponíveis: Windows 64 bits e Linux;
versão inicial: 1.5.0. `/startgh` e `/creategh` retornam 410; integrar pelo endpoint validado.

O formulário usa CSRF. Ao importar/exportar modelos, o token CSRF da página atual é preservado e não entra no JSON.
`CSRF_TRUSTED_ORIGINS` inclui a origem de GENURL; também aceita origens adicionais separadas por espaço na variável
homônima. Cookies ficam seguros quando PROTOCOL=https. Redirecionamento HTTPS e HSTS dependem do proxy externo.

`rdgenerator/build_inputs.py` é compartilhado com a ação decrypt-secrets: aceita somente os campos conhecidos e recusa
quebras de linha, tipos inesperados e sintaxe perigosa para os scripts de build. A ação valida tudo antes de escrever
GITHUB_ENV e lê a senha do ZIP pela variável de ambiente. Os callbacks de upload mantêm autenticação por token de build.

Chamadas ao GitHub têm timeout de conexão/leitura. Downloads são enviados por streaming e arquivos ausentes retornam 404.
Dados, clientes, pacotes temporários e arquivos .env são excluídos do contexto Docker. O CI constrói a imagem, roda a suíte
e o teste de fumaça nos PRs para master, sem publicar. Depois do merge, testa novamente e publica a imagem. A suíte roda
incluindo a integração com a ação real:

```bash
docker run --rm --network none -e DB_PATH=/tmp/rdgen-test/db.sqlite3 \
  -v "$PWD/.github/actions/decrypt-secrets:/opt/rdgen/.github/actions/decrypt-secrets:ro" \
  --entrypoint python rdgen-nextec:teste manage.py test rdgenerator
```

Sem as variáveis obrigatórias, o gerador continua retornando 503 e o contêiner deve ficar unhealthy. Preencher no Portainer
GERADOR_GH_TOKEN, GERADOR_ZIP_SENHA (igual ao segredo ZIP_PASSWORD no GitHub) e GERADOR_SH_SECRET; depois Pull and redeploy.
Não trocar o healthcheck para esconder a falta de configuração. SECRET_KEY vazia usa a chave persistente no volume.

## Arquivo provisório (servidor antigo)

`atualizar-servidor.sh` atualiza o rdgen **antigo** (fora da stack) por cron. Fica obsoleto quando o servidor antigo for
desligado; pode ser removido.

## Trava de integridade (CI)

`node .github/scripts/verificar-integridade.mjs` roda em todo PR (workflow "Integridade do repositorio", sem filtro de caminho,
sem dependências). Falha listando os arquivos se `.sh`, `.service`, `.timer`, Dockerfile ou workflow estiver com CRLF no
repositório, ou se um `.ps1` com caractere não ASCII não começar com BOM UTF-8 (o Windows PowerShell 5.1 quebra o parse).
`.gitattributes` força LF nesses tipos; os `.ps1` não são normalizados (o git preserva o BOM).


## Gerador simplificado e exclusão de itens (13/10/2026)

- `generator.html`: modo simples por padrão (plataforma, nome do instalador e do app, cliente, versão do pacote, ícone, notas); servidor, segurança, aparência, permissões e modelos ficam em "Avançado", recolhido. Erro em campo avançado abre a seção e aparece no campo. Nenhum campo exigido pelo build foi removido.
- Exclusão: `DELETE /nextec/geracoes/<uuid>/excluir/` e `POST /nextec/geracoes/excluir/` (`{"uuids": [...]}` ou `{"scope": "failed"}`). Exige identidade do Access e o cabeçalho `X-Nextec-Acao: excluir`. Recusa item em andamento (409 `in_progress`) e item já baixado para Atualizações sem `?confirmar=1` / `confirm_imported` (409 `imported`). Apaga só `exe/<uuid>`, `png/<uuid>` e `temp_zips/secrets_<uuid>.zip`; registra no logger `rdgenerator.audit`.
- Migração 0006 (`imported_at`): rode `python manage.py migrate` ao atualizar.
