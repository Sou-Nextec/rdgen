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
| `NX_URL_LINK`, `NX_DOWNLOAD_LINK`, `NX_COMPANY`, `NX_APP_NAME` | Links, empresa e nome padrão do app |
| `NX_LOCK_SERVER` | `1` (padrão) trava os campos acima, no formulário e no servidor |
| `NX_ICON_FILE`, `NX_LOGO_FILE` | Imagens padrão (PNG quadrado) quando nenhuma é enviada |
| `NX_ALLOWED_EMAILS` | E-mails autorizados a gerar (vírgula ou espaço). Vazio = quem passa pelo Access. Veja "Quem pode gerar" |
| `WEB_CONCURRENCY` | Processos do gunicorn (padrão 2) |

Sem `NX_SERVER_HOST` o gerador se comporta como o original.

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
que o campo `token` continua sendo exportado como `env.token` (a ação `decrypt-secrets` exporta todas as chaves).

## Arquivo provisório

`atualizar-servidor.sh` atualiza o rdgen **antigo** (fora da stack) por cron. Fica obsoleto quando o servidor antigo for
desligado; pode ser removido.
