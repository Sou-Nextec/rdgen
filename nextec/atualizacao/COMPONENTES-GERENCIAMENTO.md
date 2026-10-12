# Componentes de gerenciamento nos pacotes

MSI e EXE instalado distribuem o mesmo agente Windows transacional. EXE portátil não registra tarefas privilegiadas. O atualizador já incorporado verifica o manifesto assinado; o agente de senha é um componente separado.

O pacote não contém chave global nem token de máquina. A presença do arquivo não significa cadastro ativo: a tarefa de senha Windows depende do provisionamento autorizado. No Linux o timer é instalado, condicionado a `/var/lib/nextec-connect/agent-config.json`, e depende de provisionamento e ativação pelo coordenador.

O agente Linux valida o executável do serviço e seu ID antes de aplicar senha permanente do RustDesk. Não altera credenciais do sistema Linux. Exige API com transaction_v1 (patch 0027), HTTPS, identidade consistente e ACK da aplicação. Rejeita redirecionamentos com credenciais, downgrade e confirmação divergente.

Validação realizada: teste de construção WiX sem compilador real passou; 19 regressões Linux e reconstrução/inspeção de DEB fixture passaram em container isolado no APP03. CI ainda precisa comprovar MSI/EXE reais e instalação Windows. Homologação Windows Server 2022, sessão através de rotação e provisionamento automático ponta a ponta continuam pendentes.

A proveniência do agente Windows está em `Agente-Senha-Nextec.provenance.txt`, com commit e hash. Alteração no agente exige reconstrução dos pacotes; imagem do painel não substitui automaticamente arquivo antigo na máquina.
