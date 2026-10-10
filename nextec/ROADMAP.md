# Roadmap do Nextec Connect

## Entregue nesta versão do gerador

- Versão própria do gerador em `rdgenerator/VERSION` (`2.0.1`), separada da versão-base do RustDesk e da versão publicada para os clientes.
- Interface do gerador e telas de resultado em português, com identidade visual Nextec.
- Aba **Identidade visual** para enviar, pré-visualizar e restaurar ícone, logo e tela de privacidade. O volume persistente já usado pelo banco mantém os arquivos após recriações do container.
- Arquivos PNG são validados por tamanho, formato e dimensões antes de serem salvos.
- Corrigida a condição lógica da tela de espera para reconhecer corretamente os builds Windows.

## Próximos itens

### Prioridade 1 — personalização visual do MSI

**Estado atual:** a tela do instalador tem duas artes configuráveis no WiX: o bitmap lateral do print (493 × 312 px) e a faixa superior (493 × 58 px). O gerador ainda não aplica esses arquivos aos builds.

**Bloqueio:** os workflows Windows executam código de repositórios externos em runner próprio e usam segredos no fluxo de upload. A revisão automática de segurança recusou incluir essa alteração porque o build poderia expor os segredos ou comprometer o runner.

**Trabalho:** separar a compilação de código externo do job que usa segredos, usar runner isolado e sem dados persistentes para o build, e liberar ao job de publicação apenas artefatos validados. Depois, habilitar o envio das duas imagens e a prévia no gerador.

### Prioridade 1 — migração EXE para MSI sem perder a máquina

**Causa identificada:** o MSI-base do RustDesk 1.5.0 contém a ação WiX `BlockSelfInstalledApp`, acionada quando `APP_WINDOWS_INSTALLER` ou `APP_WINDOWS_INSTALLER32` vale `#0`. Essa regra interrompe a instalação MSI sobre a instalação feita pelo EXE, que é exatamente a mensagem do print: “installed by self-installation method”. A sequência de major upgrade do MSI só cobre instalações MSI compatíveis.

**Trabalho:** criar uma migração explícita que detecte o modo EXE, preserve ID/configuração e permissões, remova a instalação antiga com segurança e instale o MSI. Implementar backup e recuperação em caso de falha e validar em uma VM Windows com instalações x64 e x86. Não liberar para clientes sem comprovar que o ID RustDesk permanece igual após atualização, reinstalação e rollback.

**Referência de implementação:** [`Package.wxs` do RustDesk 1.5.0](https://github.com/rustdesk/rustdesk/blob/1.5.0/res/msi/Package/Package.wxs), ação `BlockSelfInstalledApp` e condição `APP_WINDOWS_INSTALLER` / `APP_WINDOWS_INSTALLER32`.

### Prioridade 1 — atualização automática dentro de EXE e MSI

**Estado atual:** `nextec/atualizacao/Instalar-Nextec.ps1` consulta a versão, confere SHA-256, instala MSI e cria uma tarefa diária como `SYSTEM`. Esse fluxo é executado por um script de instalação separado; os pacotes EXE/MSI gerados pelo RDGen ainda não carregam o agente nem registram essa tarefa. O script atual baixa MSI, então uma instalação feita pelo EXE também precisa da migração descrita acima.

**Trabalho:** incluir um agente de atualização nos dois instaladores, registrar a tarefa com a identidade adequada, validar assinatura digital e hash, tratar máquina offline, falha, rollback e atualização simultânea. Separar três versões: versão do gerador, versão-base RustDesk e versão do cliente Nextec publicado no painel. Testar instalação limpa e atualização silenciosa em Windows antes de ativar rollout.

### Prioridade 1 — endurecer os padrões de configuração

**Ponto encontrado:** `rdgen/settings.py` ainda contém valores padrão de desenvolvimento para segredos e `ALLOWED_HOSTS='*'`. O gerador já mostra erro de configuração incompleta para algumas variáveis, mas isso não substitui exigir segredos fortes e hosts explícitos na inicialização de produção.

**Trabalho:** revisar as variáveis reais da stack e então remover defaults inseguros, validar domínios permitidos e documentar a rotação dos segredos. Fazer a mudança separada, com teste de inicialização e configuração equivalente no Portainer.

### Prioridade 2 — identidade no acesso WebView

**Causa identificada:** o perfil já aceita nome e foto, e a API do painel já devolve `display_name` e `avatar`. Porém, o launcher em `rustdesk-api-web/src/utils/webclient.js` abre `/webclient2/#/<id>` passando só o ID do dispositivo; não encaminha identidade nem foto para a sessão. O painel do Helpdesk não precisa ser alterado.

**Trabalho:** definir um contrato de identidade de curta duração entre painel, WebView e cliente que recebe a solicitação; exibir nome e foto com fallback para inicial/nome. Manter a identidade autenticada e não confiar em nome/foto enviados sem validação pelo navegador. Validar no cliente real a solicitação de permissão e a janela que hoje mostra “(web)”. A alteração do cliente RustDesk/WebView está pendente porque o código-fonte do cliente desktop não está neste workspace.

### Prioridade 2 — escolha de sessão no Linux

**Trabalho:** oferecer conexão por terminal para servidores e uma escolha do analista entre terminal e área de trabalho quando houver sessão gráfica. Associar o modo padrão ao grupo de dispositivos quando configurado. Detectar `DISPLAY`/`WAYLAND_DISPLAY` apenas como indicação, com confirmação quando houver ambiguidade; manter credenciais SSH em armazenamento seguro e registrar auditoria. O cliente Linux/desktop não está neste workspace, então esta mudança precisa ser feita e testada no repositório do cliente.

## Regras para próximas mudanças

- Alterar `rdgenerator/VERSION` e registrar a alteração em `nextec/CHANGELOG.md` quando mudar a experiência do gerador.
- Atualizar a versão do cliente somente no fluxo de release dos instaladores; não usar a versão do gerador nem a versão-base RustDesk para identificar a atualização instalada.
- Não mudar rotas ou dados do Helpdesk para personalizar a tela de consentimento.
- Bugs sem teste seguro no workspace ficam nesta lista até existir cliente/VM de validação; não marcar como resolvidos com base apenas em análise estática.
