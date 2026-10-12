# Releases assinadas do Nextec Connect

Usa a mesma chave RSA 4096 do monitoramento Nextec (ID público `8cb5b1d7f80d20cb`), com RSA PKCS#1 v1.5 e SHA-256. Só a chave pública está neste repositório. O manifesto exige `produto=nextec-connect`; um manifesto do monitoramento não autoriza a instalação do Connect.

No computador Windows em que você já assina o monitoramento, use um Python 3 e OpenSSL já instalados:

1. No painel, baixe o pedido JSON da release e o MSI autorizado.
2. Extraia o ZIP em uma pasta local e dê dois cliques em `Assinar-Connect.cmd`. O launcher chama o PowerShell 5.1 e o script junto da própria pasta; ele não aceita senha por argumento. Selecione o pedido e os pacotes locais listados nele, e desbloqueie a chave cifrada uma vez. A janela permite assinar várias releases por até 15 minutos; fechar a janela encerra a sessão.

Antes de pedir a senha, o assistente confirma que a chave local usa um formato PEM RSA cifrado suportado; chaves em texto claro são recusadas. O desbloqueio fica em `SecureString` na memória da janela PowerShell. Um timer da janela encerra a sessão ao completar 15 minutos mesmo enquanto um seletor de arquivo ou aviso estiver aberto; a contagem usa relógio monotônico. Para cada release, a senha passa em bytes UTF-8 por stdin ao processo local de assinatura e ao OpenSSL, nunca por argumentos, variáveis de ambiente, arquivos ou logs; isso mantém compatibilidade com Windows PowerShell 5.1 e senhas Unicode. Fechar a janela ou vencer o prazo descarta o `SecureString`; buffers temporários de caracteres e bytes são limpos da melhor forma possível pelo runtime.

## Assinar um pedido recebido do painel

O painel pode fornecer um pedido JSON restrito com os pacotes Windows e/ou Linux. Para usar o fluxo local, selecione localmente exatamente os arquivos listados no pedido; o helper não baixa URLs.

```powershell
powershell -ExecutionPolicy Bypass -File .\assinar-pedido-connect.ps1 -Pedido .\pedido-connect.json -Msi .\Nextec-Connect.msi
```

O assistente valida pedido, hash e tamanho de cada pacote local; para MSI também confere o produto `Nextec-Connect` e `ProductVersion`. Para DEB lê somente o arquivo `control` do arquivo de controle, sem extrair conteúdo do pacote, e confere `Package`, `Version` e `Architecture`. O parser local aceita control.tar compactado em gzip, xz ou bzip2 e rejeita formatos desconhecidos, incluindo zstd, sem tentar executar ferramentas externas ou extrair o pacote. A sequência precisa ser maior que o contador local; quando não há contador local, a sequência reservada pelo servidor pode ser usada diretamente. O pedido só aceita estes campos, sem extensões:

```json
{
  "produto": "nextec-connect",
  "formato": 1,
  "versao": "2.0.3",
  "sequencia": 8,
  "windows": {
    "arquivo": "files/nextec-acesso-2.0.3.msi",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "tamanho": 12345678
  }
}
```

Para release só Linux, omita `windows` e inclua `linux` com `amd64`, `arm64` ou ambos; cada registro contém os mesmos campos `arquivo`, `sha256` e `tamanho`, usando `files/nextec-acesso-<versao>-<arquitetura>.deb`. O pedido precisa conter pelo menos uma plataforma. Produto, formato, caminhos, data de publicação e validade não podem ser escolhidos pelo pedido: o helper fixa os valores contratuais e gera validade de 30 dias. A assinatura continua sendo RSA PKCS#1 v1.5/SHA-256 com a chave cifrada local e a senha desbloqueada uma vez para a sessão de 15 minutos. O manifesto só é gravado depois de conferir a assinatura contra a chave pública Nextec. A saída fica em `Documentos/Nextec/Connect/Releases/<versao>-<sequencia>`.

O servidor reserva sequências globalmente. O helper aceita uma sequência de servidor maior que o contador local, inclusive no primeiro uso, mas sempre recusa reutilizar ou retroceder a sequência local. A API e os atualizadores ainda fazem suas próprias verificações de assinatura, hash, validade e replay. O arquivo persistente `manifest-sequence.lock` usa lock do sistema operacional; se o assinador ou o PowerShell forem encerrados à força, o sistema libera o bloqueio e a próxima sessão pode continuar sem recuperação manual.

O navegador e o servidor não recebem a chave privada. O publicador de linha de comando anterior continua disponível para publicações que ainda não recebem pedido JSON:

```powershell
python nextec/atualizacao/publicar-connect.py --msi "C:\Downloads\Client-Nextec-Connect.msi" --versao 2.0.3 --sequencia 1 --chave "D:\Chaves Nextec\nextec-atualizador-privada.pem" --saida "C:\Releases\Connect-2.0.3"
```

Para incluir Linux, passe também os `.deb` gerados pelo RDGen. O nome dos arquivos precisa indicar a arquitetura:

```powershell
python nextec/atualizacao/publicar-connect.py --msi "C:\Downloads\Client-Nextec-Connect.msi" --deb-amd64 "C:\Downloads\Client-Nextec-Connect-x86_64.deb" --deb-arm64 "C:\Downloads\Client-Nextec-Connect-aarch64.deb" --versao 2.0.3 --sequencia 2 --chave "D:\Chaves Nextec\nextec-atualizador-privada.pem" --saida "C:\Releases\Connect-2.0.3"
```

O caminho `D:\Chaves Nextec\nextec-atualizador-privada.pem` é apenas exemplo; o caminho real da chave cifrada precisa ser escolhido no computador do assinador. OpenSSL pede a senha diretamente; ela não passa por argumentos, ambiente ou logs. O publicador confere se a assinatura corresponde à chave pública confiável antes de salvar os arquivos. Nunca envie a chave privada para o gerador, painel, CI ou clientes.

Cada autorização do Connect usa uma sequência maior que a anterior, independente da sequência do monitoramento. O número da versão é o da release do cliente; não precisa coincidir com a versão do gerador. O manifesto vence em 30 dias. Para renovar, gere outro manifesto para o mesmo MSI com sequência maior e atualize a autorização no painel.

Saída: `manifesto-connect.json` e `manifesto-connect.json.sig`. No painel, envie o MSI e os `.deb` na mesma versão, escolha **Autorizar**, envie esses dois arquivos e publique primeiro para o grupo piloto. O painel confere produto, assinatura, versão, caminho, tamanho, hash e validade; os atualizadores repetem a conferência e recusam sequências antigas ou reutilizadas com conteúdo diferente.

O MSI e o EXE instalado incluem atualizador, agente de senha e coordenador de cadastro. A instalação registra o atualizador diário e o coordenador SYSTEM de cinco minutos, inclusive offline. O EXE portátil não registra tarefas. O DEB inclui os três componentes e seus timers systemd. Nenhum pacote contém uma credencial de cadastro global.

Na primeira ativação, vincule a máquina a um cliente e escolha **Cadastrar máquina** no painel. Baixe sua autorização, válida por 15 minutos. Na sessão remota confiável do Windows, execute como administrador o `Coordenar-Agente-Nextec.ps1 -Receber` instalado em `C:\ProgramData\Nextec\Acesso`; o seletor recebe o `bootstrap.json` sem senha ou token em argumentos. O coordenador conclui o cadastro e registra a tarefa de senha. No Linux, entregue o arquivo como root:root 0600 em `/var/lib/nextec-connect/bootstrap.json`; o timer completa o cadastro e inicia o agente. As verificações seguintes são automáticas. Revogação exige nova autorização explícita.

Na desinstalação verdadeira, as tarefas/timers são removidos; reparo e upgrade preservam identidade e configuração. A publicação de atualizações permanece sob controle do administrador: assine e valide um piloto antes de ampliar a distribuição.

O manifesto assinado autentica cada pacote para o atualizador; não altera os avisos do Windows sobre executáveis sem Authenticode. A primeira instalação continua dependendo de um canal confiável. AppImage, Flatpak, RPM e pacotes já instalados antes desta mudança ainda não recebem o timer; eles precisam de fluxos próprios/instalação da nova versão.

Estado: verificadores, publicadores e empacotamento do atualizador estão no código. O CI precisa confirmar o conteúdo do MSI e dos `.deb`; a validação de atualização real em VM e a preservação de ID no primeiro update ainda são gates antes de publicar uma release para todos. Instalações anteriores ao MSI com atualizador precisam receber uma versão-base por canal confiável para registrar a tarefa.
