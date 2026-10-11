# Gerador Nextec

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

