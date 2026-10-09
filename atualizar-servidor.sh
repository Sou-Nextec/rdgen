#!/usr/bin/env bash
# Atualiza o rdgen do servidor sozinho: se saiu mudança no GitHub (Sou-Nextec/rdgen, branch master), puxa, reconstrói a
# imagem e reinicia só o rdgen. Sem mudança, não faz nada.
#
# Uso (na pasta do rdgen, onde está o docker-compose.yml):
#   sudo ./atualizar-servidor.sh               roda uma verificação agora
#   sudo ./atualizar-servidor.sh --instalar    agenda no cron para rodar a cada 15 minutos
#   sudo ./atualizar-servidor.sh --remover     tira o agendamento
#
# Variáveis opcionais: RDGEN_BRANCH (padrão master), RDGEN_LOG (padrão /var/log/rdgen-atualizacao.log), SERVICO (padrão rdgen)
set -u

PASTA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAMO="${RDGEN_BRANCH:-master}"
LOG="${RDGEN_LOG:-/var/log/rdgen-atualizacao.log}"
SERVICO="${SERVICO:-rdgen}"
DOCKER="${DOCKER_BIN:-docker}"
AGENDA='*/15 * * * *'

log() { printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG" >&2; }

case "${1:-}" in
  --instalar)
    linha="$AGENDA $PASTA/atualizar-servidor.sh >> $LOG 2>&1"
    ( crontab -l 2>/dev/null | grep -v 'atualizar-servidor.sh' ; echo "$linha" ) | crontab -
    echo "Agendado: $linha"
    exit 0 ;;
  --remover)
    crontab -l 2>/dev/null | grep -v 'atualizar-servidor.sh' | crontab -
    echo "Agendamento removido."
    exit 0 ;;
esac

cd "$PASTA" || exit 1

# nunca duas execuções ao mesmo tempo (o build leva alguns minutos)
if command -v flock >/dev/null 2>&1; then
  exec 9>"/tmp/rdgen-atualizacao.lock"
  flock -n 9 || { echo "Já existe uma atualização em andamento."; exit 0; }
else
  TRAVA="/tmp/rdgen-atualizacao.lock.d"
  # trava velha (processo morreu): mais de 2 horas, descarta
  [ -d "$TRAVA" ] && [ -n "$(find "$TRAVA" -maxdepth 0 -mmin +120 2>/dev/null)" ] && rmdir "$TRAVA" 2>/dev/null
  mkdir "$TRAVA" 2>/dev/null || { echo "Já existe uma atualização em andamento."; exit 0; }
  trap 'rmdir "$TRAVA" 2>/dev/null' EXIT
fi

if [ ! -d .git ]; then
  log "ERRO: $PASTA não é um clone do git. Faça: git clone https://github.com/Sou-Nextec/rdgen.git e use essa pasta (ou copie seu docker-compose.yml e .env para lá)."
  exit 1
fi

git fetch --quiet origin "$RAMO" || { log "ERRO: não consegui consultar o GitHub (rede?)."; exit 1; }
local_=$(git rev-parse HEAD)
remoto=$(git rev-parse "origin/$RAMO")
if [ "$local_" = "$remoto" ]; then
  exit 0   # sem novidade
fi

log "Novidade no GitHub: ${local_:0:7} -> ${remoto:0:7}. Atualizando..."
if ! git merge --ff-only "origin/$RAMO" >/dev/null 2>&1; then
  log "ERRO: não foi possível avançar a pasta (há alteração local nos arquivos versionados). Resolva à mão: git status"
  exit 1
fi

# se o compose tem a seção build, reconstrói por ele; senão constrói a imagem usada pelo serviço
if grep -qE '^[[:space:]]+build:' docker-compose.yml 2>/dev/null; then
  "$DOCKER" compose build "$SERVICO" >>"$LOG" 2>&1 || { log "ERRO no build (veja $LOG). O rdgen continua na versão anterior."; exit 1; }
else
  imagem=$("$DOCKER" compose config 2>/dev/null | awk '/^[[:space:]]+image:/ {print $2; exit}')
  [ -z "$imagem" ] && imagem="nextec/rdgen:master"
  "$DOCKER" build -t "$imagem" . >>"$LOG" 2>&1 || { log "ERRO no build (veja $LOG). O rdgen continua na versão anterior."; exit 1; }
fi

"$DOCKER" compose up -d "$SERVICO" >>"$LOG" 2>&1 || { log "ERRO ao reiniciar o rdgen (veja $LOG)."; exit 1; }
log "rdgen atualizado para ${remoto:0:7}."
