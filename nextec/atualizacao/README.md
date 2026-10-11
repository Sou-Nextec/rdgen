# Releases assinadas do Nextec Connect

Usa a mesma chave RSA 4096 do monitoramento Nextec (ID público `8cb5b1d7f80d20cb`), com RSA PKCS#1 v1.5 e SHA-256. Só a chave pública está neste repositório. O manifesto exige `produto=nextec-connect`; um manifesto do monitoramento não autoriza a instalação do Connect.

No computador em que você já assina o monitoramento:

```powershell
python nextec/atualizacao/publicar-connect.py --msi "C:\Downloads\Client-Nextec-Connect.msi" --versao 2.0.3 --sequencia 1 --chave "D:\Chaves Nextec\nextec-atualizador-privada.pem" --saida "C:\Releases\Connect-2.0.3"
```

Para incluir Linux, passe também os `.deb` gerados pelo RDGen. O nome dos arquivos precisa indicar a arquitetura:

```powershell
python nextec/atualizacao/publicar-connect.py --msi "C:\Downloads\Client-Nextec-Connect.msi" --deb-amd64 "C:\Downloads\Client-Nextec-Connect-x86_64.deb" --deb-arm64 "C:\Downloads\Client-Nextec-Connect-aarch64.deb" --versao 2.0.3 --sequencia 2 --chave "D:\Chaves Nextec\nextec-atualizador-privada.pem" --saida "C:\Releases\Connect-2.0.3"
```

O caminho da chave é um exemplo: use a chave cifrada que já utiliza no monitoramento. OpenSSL pede a senha diretamente; ela não passa por argumentos, ambiente ou logs. O publicador confere se a assinatura corresponde à chave pública confiável antes de salvar os arquivos. Nunca envie a chave privada para o gerador, painel, CI ou clientes.

Cada autorização do Connect usa uma sequência maior que a anterior, independente da sequência do monitoramento. O número da versão é o da release do cliente; não precisa coincidir com a versão do gerador. O manifesto vence em 30 dias. Para renovar, gere outro manifesto para o mesmo MSI com sequência maior e atualize a autorização no painel.

Saída: `manifesto-connect.json` e `manifesto-connect.json.sig`. No painel, envie o MSI e os `.deb` na mesma versão, escolha **Autorizar**, envie esses dois arquivos e publique primeiro para o grupo piloto. O painel confere produto, assinatura, versão, caminho, tamanho, hash e validade; os atualizadores repetem a conferência e recusam sequências antigas ou reutilizadas com conteúdo diferente.

Os instaladores Nextec-Connect incluem a checagem diária. O MSI registra uma tarefa do Windows como SYSTEM; o EXE é um bootstrapper que abre o mesmo MSI, então os dois modos ficam registrados como instalação MSI. O `.deb` inclui um timer systemd diário e o agente Python. A publicação continua desligada até um administrador enviar os arquivos, autorizar o manifesto assinado e escolher um piloto ou liberar todos.

O manifesto assinado autentica cada pacote para o atualizador; não altera os avisos do Windows sobre executáveis sem Authenticode. A primeira instalação continua dependendo de um canal confiável. AppImage, Flatpak, RPM e pacotes já instalados antes desta mudança ainda não recebem o timer; eles precisam de fluxos próprios/instalação da nova versão.

Estado: verificadores, publicador e empacotamento dos agentes estão no código. O CI precisa confirmar o conteúdo do MSI e os `.deb`; a validação de atualização real em VM e a preservação de ID no primeiro update ainda são gates antes de publicar uma release para todos. Clientes já instalados precisam receber a nova versão por um canal confiável para instalar a tarefa.
