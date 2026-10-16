# Gerador Nextec

## 2.3.9

Acabamento da tela Gerar cliente (itens P3). Só interface; nenhum script do agente mudou.

- **Plataforma sem quebra de linha:** o botão diz "Windows" (cabia mal em 390 px) e a dica informa que é de 64 bits. O valor enviado não mudou.
- **Alterar configurações remotamente** explica por que vem desmarcado.
- **Desenvolvimento (nightly)** vai para o fim da lista de versões-base, com "pode falhar" no rótulo. O valor `master` e a versão padrão (1.5.0) não mudaram, então modelos salvos seguem válidos.

## 2.3.8

Refino da tela Gerar cliente, itens P2 (hierarquia e fluxo). Só interface e validação; nenhum script do agente mudou.

- **Modelos sem ruído:** o topo tem só "Começar de um modelo", que carrega ao escolher. "Salvar como modelo" e "Excluir modelo" ficam perto do botão Gerar (Excluir só aparece com um modelo escolhido).
- **Sem janelas nativas:** nome do modelo, exclusão e erros de importação JSON usam confirmação e mensagens na própria tela (`prompt`, `confirm` e `alert` saíram; no iframe do painel eles ficavam fora de vista ou eram bloqueados). Escape cancela e o foco volta ao botão.
- **Nome do aplicativo acompanha o instalador** até a pessoa editar o dele (e volta a acompanhar se ficarem iguais).
- **Cliente específico exige o cliente:** "Destinado a" e "Cliente" ficam lado a lado e o campo vira obrigatório nesse perfil, no formulário e no servidor (API incluída).
- **Versão do pacote** deixa de ser um campo com rótulo e vira um selo na nota do botão Gerar (o valor segue sendo o do gerador).
- **Menos repetição:** o bloco "Sobre nomes, versões e acesso" sai; a conta que gera aparece na nota do botão.
- **Importar JSON:** escolher o mesmo arquivo duas vezes funciona e a importação não se repete (o evento era registrado a cada clique); o seletor de modelos não entra mais no JSON exportado; o aviso de valores incompatíveis usa o estilo de erro do tema.

## 2.3.7

Refino da tela Gerar cliente (itens P1 da análise de UX/UI). Só interface e validação; nenhum script do agente mudou.

- **Inscrição desativada deixa de parecer sucesso:** quando o gerador não consegue a credencial de inscrição, a caixa vira alerta ("Atenção: confira antes de gerar"), o botão Gerar fica desligado e só libera depois de marcar a confirmação de gerar mesmo assim. Sem aviso, nada muda. Chave pública ausente com servidor configurado também vira alerta.
- **Cabeçalho legível no modo escuro do sistema:** fora do painel ("Abrir em outra aba"), o título branco ficava sobre fundo claro; agora usa a superfície escura, como o tema escuro do painel.
- **Nomes sem pegadinha:** Nome do instalador e do aplicativo vêm preenchidos com `Nextec-Connect` (valor real, não placeholder; os exemplos agora dizem "Ex.:"). Em Tentar de novo de item antigo sem o nome do aplicativo, o campo fica vazio para conferir. O nome do aplicativo é validado enquanto digita (espaço, acento e símbolos), com a mesma regra do servidor, e o envio é barrado com foco no campo.
- **Servidor só com o que é do servidor:** Endereço dos links e Endereço das atualizações saem do bloco "Servidor Nextec" para "Endereços do aplicativo", com texto que diz se estão fixados ou opcionais.
- **Modelos salvos:** a confirmação de inscrição não entra no modelo (checkbox sem nome é ignorado).

## 2.3.6

A versão do instalador gerado passa a ser a versão do gerador (`rdgenerator/VERSION`), para saber exatamente qual gerador e qual conjunto de scripts do agente estão dentro do pacote.

- **Fonte única da versão:** o formulário não pede mais a versão do pacote (mostra a do gerador). O campo segue aceito por compatibilidade com API e modelos salvos, mas o servidor ignora o valor enviado e grava a do gerador (antes um 2.0.9 manual ficava no instalador mesmo com o agente novo dentro).
- **Onde a versão entra:** ProductVersion do MSI (`X.Y.Z.0`, limites 255.255.65535 validados), `Version` da DEB, `nextec-marker.json` (`package_version`, `generator_version` e `agent_hash`, hash do conjunto de scripts calculado de `FONTE-AGENTE.json`), registro `HKLM\SOFTWARE\Nextec\Agente` (`Version`, `GeneratorVersion`, `AgentHash`; `Acesso\Versao` segue como antes), itens gerados e pedido de importação para Atualizações. 2.3.x é maior que 2.0.x, então instalações antigas continuam atualizáveis.
- **Trava no CI:** `nextec/conteudo-pacote.lock` guarda versão e hash do conteúdo empacotado (scripts do agente Windows e Linux, `FONTE-AGENTE.json`, imagens MSI, `build-msi.ps1`, `install-msi-artwork.ps1`, `build-setup-exe.ps1`). `rdgenerator/test_pacote_versao.py` falha com "conteúdo do pacote mudou: suba a versão do gerador" se o conteúdo mudar sem subir `rdgenerator/VERSION`. Atualização: `python manage.py atualizar_lock_pacote`.
- **Workflows:** o build copia `FONTE-AGENTE.json` junto dos scripts para o `build-msi.ps1` identificar o conjunto; `Validar MSI Nextec` usa a versão do gerador em vez de 2.0.7.

## 2.3.5

Agente ressincronizado com o painel 2.11.24 (master 7dacd85, PRs #92 a #95), por `nextec/scripts/sincronizar-agente.py`, sem edição manual.

- **Scripts atualizados:** `Agente-Senha-Nextec.ps1` (estado honesto 0035, troca rápida e intervalo único 0036, `app_name` por máquina 0037, `client_settings_locked`), `Coordenar-Agente-Nextec.ps1` e `Provisionar-Agente-Nextec.ps1` (reinstalação sem beco, sondagem `probe`, reparo com a credencial existente). `Instalar-Nextec.ps1` e `Manifesto-Connect.ps1` não mudaram. `FONTE-AGENTE.json` e a proveniência apontam para o novo commit; MSI, EXE e DEB empacotam o conjunto com hash instalado = pacote = registro.
- **Sem `disable-settings` com o agente:** já garantido desde 2.3.4 (`test_settings_lock.py`); mantido.
- **Linux:** os arquivos Linux do rdgen não fazem parte da fonte única e seguem como estavam.

## 2.3.4

- **"Desativar configurações" não quebra mais a senha automática:** com o agente (`nx_agent` ligado), o gerador não grava mais `disable-settings`, que no RustDesk 1.5.0 faz `--password` e `--option` responderem "Settings are disabled!" (o agente registrava `password_apply_failed` a cada rodada e o painel ficava em "Aguardando a primeira troca"). No lugar, entram as opções `hide-general-settings`, `hide-security-settings`, `hide-network-settings`, `hide-server-settings`, `hide-proxy-settings`, `hide-websocket-settings`, `hide-remote-printer-settings` e `hide-stop-service`, que ocultam as mesmas abas na interface e também a aba Geral (que `disable-settings` deixava editável). Sem o agente (suporte avulso), nada muda. Clientes já instalados com essa opção precisam de um instalador novo instalado por cima.

## 2.3.3

Achados da revisão do PR #45 (instalador Windows). Os scripts do agente foram ressincronizados com o painel 2.11.17.

- **Painel do instalador também no registro:** além do `nextec-marker.json`, o MSI grava o valor `Painel` em `HKLM\SOFTWARE\Nextec\Agente` (só `https://dominio` válido, com ou sem chave de inscrição). O agente lê arquivo, depois registro, depois o padrão; o cadastro manual deixa de dar `invalid_panel` com painel personalizado.
- **Reinstalação por outro painel:** instalador sem inscrição de outro painel não herda a inscrição nem a credencial do painel anterior (host normalizado); a decisão vai para o `coordenador.log`, sem segredos. O `-UrlBase` do build é preservado pelo atualizador.
- **Tarefa de senha validada por inteiro** (SYSTEM, Highest, Windows PowerShell 5.1, `-File`, `-Executar`, repetição de até 5 minutos).
- **Teste de recuperação do 401 de verdade:** `test_agent_401_integration.ps1` (HttpListener local) faz o agente empacotado/instalado receber 401 três vezes seguidas, descartar a credencial e refazer o cadastro; 1 ou 2 respostas 401 não descartam. Roda em `test-msi-build.ps1` e em `test-msi-install.ps1`. Antes, a credencial morta da máquina suja caía por erro de leitura, não por 401.
- **Provisionador ressincronizado com o painel #90 (master 09990e5):** o pacote ainda levava o fluxo que comparava o pendente do painel anterior antes de descartar ou expirar e devolvia `identity_conflict` em 0 e 20 minutos. Agora o pendente de outro painel é descartado (`pending_other_panel`) e a inscrição chega ao self-enroll; o do mesmo painel fica e expira (`pending_expired`). Também entram a troca segura de agente antigo (`-SubstituirAgenteAntigo`) e o `-UrlBase` do atualizador preservado.
- **Regressão contra o payload instalado:** `test_provisionar_outro_painel_installed.ps1` roda o Provisionar empacotado/instalado (0 e 20 min, mesmo painel, 401 triplo) em `test-msi-build.ps1`, `test-msi-install.ps1` e no workflow `Validar MSI Nextec`; os dois testes de MSI conferem hash instalado = pacote = `FONTE-AGENTE.json`.

## 2.3.2

Estabilização do instalador Windows (Fase 1).

- **Scripts do agente atualizados e com fonte única:** os scripts que o MSI instala eram uma cópia da versão 2.11.4 do painel e não tinham as correções seguintes. Agora são cópias exatas de um commit do painel, feitas por `nextec/scripts/sincronizar-agente.py` e registradas em `nextec/atualizacao/FONTE-AGENTE.json`. O CI recusa PR com script alterado à mão ou diferente da origem.
- **Agente acha o serviço do RustDesk em máquina real** (correção do painel 2.11.16): o serviço roda como LocalSystem e grava em `ServiceProfiles\LocalService`; o agente procurava em `systemprofile` e nenhuma máquina se inscrevia.
- **O agente nunca desfaz a instalação do app:** as ações do MSI do atualizador e do coordenador passaram de `Return="check"` para `Return="ignore"`. Antes, qualquer falha de script (por exemplo, arquivo de agente antigo com outra permissão) fazia o MSI inteiro voltar atrás com erro 1603. A falha fica em `C:\ProgramData\Nextec\Acesso\coordenador.log`.
- **Painel inválido barrado no build:** só `https://dominio` em minúsculas, sem porta nem caminho (o formato que o agente aceita). Antes o build gerava um instalador que nunca se inscrevia.
- **Revisão do PR:** o painel do build (`https://dominio`) vai no `nextec-marker.json` (campo `painel`) e o coordenador o copia para a pasta de dados, então o agente acha o painel certo mesmo quando o instalador sai **sem** chave de inscrição; instalador sem `inscricao.json` não herda a de outro painel; scripts ressincronizados com o painel (credencial só aposentada depois de o servidor aceitar o cadastro novo, 401 seguidos, tarefa de senha validada por inteiro).
- **Achado pelo teste real, corrigido no painel 2.11.16:** o `rustdesk.exe` é um programa de janela e o PowerShell não espera nem captura a saída de um programa assim quando ela é atribuída (`$x = & exe`); a troca de senha rodava sem ninguém conferir o "Done!" e nunca era confirmada ao painel. O agente agora inicia o cliente com a saída redirecionada e espera de verdade.
- **Fixture do teste real com o nome `RustDesk`:** o binário oficial tem o nome compilado e `--password` só funciona quando o app instalado é o do próprio binário; com outro nome ele responde "Installation and administrative privileges required!". Nome livre continua coberto por `test-msi-build.ps1`.
- **Teste de instalação real agora prova o cadastro completo:** um painel falso em HTTPS (443, certificado confiado só no runner, `hosts` para 127.0.0.1) responde o protocolo real. O agente instalado, rodando como SYSTEM, precisa se inscrever (HTTP 200), gravar a credencial, registrar a tarefa de senha, propor a senha, aplicá-la no RustDesk (`--password`, "Done!") e confirmar; o teste confere o ID inscrito contra o `--get-id` do serviço.
- **Teste de instalação real com máquina "suja":** o CI instala o MSI num Windows Server 2022 que já tem um agente antigo (permissão herdada e credencial morta), confere que a instalação passa, que o arquivo antigo foi trocado, e roda o coordenador de verdade como SYSTEM contra o serviço RustDesk instalado: ele precisa achar o serviço, aposentar a credencial morta e tentar a inscrição.

## 2.3.1

- Trava de CI: `.github/scripts/verificar-integridade.mjs` barra CRLF em `.sh`, `.service`, `.timer`, Dockerfile e workflows e `.ps1` com acento sem BOM UTF-8; `.gitattributes` com LF para esses tipos. BOM adicionado a 5 `.ps1` que tinham acento sem ele. Sem mudança de comportamento do gerador.

## 2.3.0

- Nome do app livre: o agente (Coordenar/Provisionar/Agente-Senha, atualizador, registro) entra pelo flag `nx_agent` do build (ligado por padrão, desligado só no suporte avulso), não mais pelo sufixo do nome. Substitui a regra por sufixo do #40 em MSI, EXE e DEB.
- Marcador `nextec-marker.json` `{v,app,upgrade_code}` e registro `HKLM\SOFTWARE\Nextec\Agente` `{InstallDir,AppName}`.
- Linux: atualizador e coordenador descobrem o cliente sem nome fixo: marcador `nextec-marker.json`, serviço systemd (nome ou ExecStart) e varredura limitada; falha explícita com o que foi procurado, nunca ID vazio.
- Painel configurável: sem domínio fixo no MSI nem nos scripts Linux; vem do build (`enroll_panel`/`inscricao.json`), só https.
- A chave de inscrição automática (2.2.0) continua alimentando o `inscricao.json` e o marcador.


## 2.2.0

- A chave de inscrição agora é obtida automaticamente: a cada build o gerador a busca no painel pela rede interna (`http://rustdesk:21114/api/nextec/gen/enroll-key`, timeout de 3 s, segredo compartilhado `SH_SECRET`). Girar a chave no painel não exige mexer na stack nem no Portainer.
- `NX_ENROLL_KEY` virou override opcional, usado só quando a busca falha; `NX_PANEL_INTERNAL_URL` ajusta (ou, vazio, desliga) a busca. Nem a chave nem o segredo são gravados em banco, modelos ou logs.
- Requer o painel 2.11.8 (patch `0033-gen-enroll-key.patch`). Testes com painel falso: sucesso, rede falha, segredo errado, chave malformada e fallback.

## 2.1.0

- Scripts do agente ressincronizados com a master do painel (a81ec60, PR #77): Coordenar com `-ArquivoAutorizacao` para o `Ativar-Nextec-<ID>.cmd`; inclui a correção do Replace nulo (#73).

- Inscrição global: todo instalador (MSI, EXE e DEB) leva `inscricao.json` com `{"v":1,"painel","chave"}` para a máquina se inscrever sozinha no painel.
- A chave vem da variável `NX_ENROLL_KEY` do contêiner e viaja só no pacote cifrado do build; não é gravada em banco, modelos, exportações, logs nem erros.
- Sem `NX_ENROLL_KEY` o build continua e gera instalador sem `inscricao.json`, com aviso no formulário, na espera e na saída do build.
- No MSI/EXE o arquivo é o componente `Nextec.Enrollment`, fora dos scripts assinados (hashes preservados); no DEB do Nextec-Connect fica em `/usr/lib/nextec-connect/inscricao.json` (`root:root` 0600), a fonte que o coordenador Linux lê. Scripts do agente e coordenadores sincronizados com o painel (commit c061480) e teste integrado do POST self-enroll.

## 2.0.9

- Coordenador de ativação por máquina incorporado no MSI/EXE instalado e no DEB; cadastro inicial usa autorização de 15 minutos, sem credencial global no pacote.
- Tarefas SYSTEM e timers systemd de gerenciamento, reparo sem mudar identidade e remoção de tarefas na desinstalação verdadeira.
- Assinador local por duplo clique: chave cifrada, senha em memória por 15 minutos e conferência dos pacotes antes de assinar.
- Download autenticado do assistente e regressões de recuperação, chave sem cifra, encerramento abrupto e identidade.

## 2.0.8

- Gerencia logos separados para tema claro e escuro e inclui ambos nos builds Windows e Linux; o cliente alterna a arte conforme o tema.
- Adiciona um assistente local de assinatura que lê a versão do MSI e incrementa a sequência sem enviar a chave privada ao navegador, servidor ou CI.


O número nesta página acompanha a experiência do gerador (layout, organização e recursos próprios da Nextec). Ele é independente da versão-base do RustDesk escolhida em cada build e da versão publicada pelo painel para atualização dos clientes.

## 2.0.7

- Histórico persistente de gerações, com versões, perfil, carteira, autoria e erros de submissão sem guardar segredos.
- Exportação interna autenticada do MSI para Atualizações do painel.
- EXE com escolha entre execução avulsa sem instalação e instalação pelo MSI; elevação somente ao instalar.
- Versão do pacote independente da base RustDesk, propagada ao MSI e ao atualizador.
- Corrige a duração do atraso da tarefa agendada (ISO-8601) e adiciona instalação/repair reais ao teste Windows Server 2022.

## 2.0.6

- Incorpora o gerador ao painel na mesma origem, acompanhando o tema e a altura do conteúdo.
- Mostra o percentual das etapas reais do Actions e identifica a etapa que falhou. Downloads dependem dos arquivos recebidos.
- Aceita o patch Flutter já aplicado ao SDK restaurado do cache, sem ocultar incompatibilidades.
- Corrige a substituição do nome e os argumentos do compilador no instalador EXE; testa a compilação real e a integridade do MSI incorporado.
- Corrige o aviso de macOS nas gerações Windows e Linux e adiciona testes de regressão.

## 2.0.4

- Alinha cores, superfícies, tipografia, campos e estados de foco ao sistema visual do painel remoto; melhora a seleção de plataforma por teclado e telas menores.

## 2.0.5

- Corrige a largura e o espaçamento dos campos nos cartões e melhora o layout responsivo.
- Evita exibir o seletor nativo de plataforma duplicado mantendo o valor enviado pelo formulário.
- Adiciona o favicon Nextec às telas do gerador e de identidade visual.

## 2.0.3

- Permite enviar as duas artes do MSI (lateral de 493 × 312 px e faixa de 493 × 58 px) na aba Identidade visual. O gerador converte PNG ou BMP validado para BMP e o build usa essas imagens nas próximas gerações.
- Mantém a publicação da atualização pelo painel e a instalação automática dentro do EXE/MSI pendentes de um fluxo de assinatura, distribuição e migração comprovado em Windows.

## 2.0.2

- Corrige servidor de ID e API nos clientes de entrada gerados com permissões padrão.
- Aproxima o gerador das cores do painel remoto e reorganiza os campos para telas menores.
- Permite salvar modelos de configuração por usuário no banco do gerador, sem credenciais, imagens ou ajustes manuais; importação e exportação JSON continuam disponíveis.
- Explica os nomes do pacote e do aplicativo, o tema escuro e a geração de uma plataforma por vez.
- Mostra se a chave pública foi carregada do servidor e permite conferi-la no formulário.

## 2.0.1

- Gerador em português e identidade visual Nextec, com navegação clara entre geração e imagens.
- Aba persistente para ícone, logo e tela de privacidade.
- Telas de espera, sucesso e erro traduzidas para português.
- Chave pública e servidor continuam preenchidos pelo ambiente de implantação.

