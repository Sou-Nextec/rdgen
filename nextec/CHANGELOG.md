# Gerador Nextec

## 2.4.1

- **Teste de atualização por cima no CI:** o fixture constrói a versão 2.0.7 e a 2.0.8 do mesmo app; o teste instala a primeira, deixa o agente se inscrever e então instala a segunda por cima, como o atualizador faz na frota. Exige: mesmo ID do RustDesk, mesma credencial do agente (hash do arquivo), um único serviço, uma tarefa de cada, um só pacote do agente e a versão nova registrada.

- **Revisão do PR:** depois da atualização por cima, o teste dispara a tarefa de senha e exige uma troca nova aplicada no RustDesk e confirmada pelo agente já atualizado (tarefa única, SYSTEM, 5 minutos, habilitada).
- Scripts do agente sincronizados com o painel 2.13.0 (atualizador que não derruba atendimento, conferindo a sessão antes do download e antes do `msiexec`).

## 2.4.0

Instalador por cliente e instalação sem cliques extras.

- **Seletor "Cliente do painel":** a lista vem do painel (`GET /api/nextec/gen/clients`, rede interna, mesmo segredo da chave global). Escolhido o cliente, o build busca a **credencial desse cliente** (`GET /api/nextec/gen/enroll-key?group=<id>`, formato `nx2.<cliente>.<época>.<assinatura>`) e a embute no `inscricao.json`: a máquina que instalar aparece já no cliente, com a senha automática, sem Pendentes nem Atribuir. Sem cliente, o instalador continua geral.
- **Revisão do PR:** instalador por cliente sem URL do painel (`NX_API_SERVER`) ou sem o agente é recusado antes do build (503/400), em vez de sair sem `inscricao.json` com um aviso.
- **Nunca cai na chave global em silêncio:** se o painel não entregar a credencial do cliente, a geração falha com mensagem clara (503) em vez de sair um instalador que cairia em Pendentes.
- **Link do painel:** `/gerador/?cliente=<id>` já abre o formulário com o cliente escolhido (menu Clientes > Baixar instalador deste cliente, painel 2.12.0).
- **EXE:** "Instalar nesta máquina" passou a ser o botão padrão (Enter); o portátil fica como alternativa. Novo modo silencioso `--silent` (ou `/S`) para GPO, RMM e scripts: instala com `msiexec /qn`, sem tela nem caixa de erro, devolvendo o código de saída.
- `build_inputs.py`, `build-msi.ps1` e `inscricao-linux.sh` aceitam os dois formatos de credencial (`nx1` global e `nx2` por cliente).
- Exige o patch 0035 da API (painel 2.12.0). Sem ele, o seletor aparece vazio e tudo segue como antes.

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

