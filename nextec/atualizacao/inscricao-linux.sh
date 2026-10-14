#!/usr/bin/env bash
# Inscricao global no pacote Linux: gera inscricao.json a partir das variaveis do build e o instala no .deb.
#   inscricao-linux.sh gerar <saida.json>        usa enroll_key e enroll_panel (secrets do build, ja mascarados)
#   inscricao-linux.sh incorporar <pacote.deb> <inscricao.json>
# A chave nunca e impressa. Sem chave, "gerar" avisa e sai com 0 sem criar arquivo (o build continua sem inscricao).
set -euo pipefail

TMP_DIR=''
cleanup() { [[ -z "$TMP_DIR" ]] || rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT

# Fonte que o coordenador Linux realmente le (INSCRICAO_SOURCE = ao lado do script); ele copia depois
# para /var/lib/nextec-connect/inscricao.json. So existe no .deb do Nextec-Connect.
DEST_DIR=/usr/lib/nextec-connect
COORDINATOR=coordenador-agente-nextec-linux.py
DEST_NAME=inscricao.json
KEY_RE='^(nx1\.[0-9]{1,12}\.[A-Za-z0-9_-]{16,128}|nx2\.[0-9]{1,10}\.[0-9]{1,12}\.[0-9a-f]{64})$'
PANEL_RE='^https?://[]A-Za-z0-9._:[-]+(/[A-Za-z0-9._~%/-]*)?$'

gerar() {
  local out=${1:?Informe o arquivo de saida}
  local key=${enroll_key:-} panel=${enroll_panel:-}
  if [[ -z "$key" && -z "$panel" ]]; then
    echo "::warning title=Instalador sem inscricao automatica::A chave de inscricao global (NX_ENROLL_KEY) nao foi fornecida; o pacote sera gerado SEM inscricao.json."
    rm -f -- "$out"
    return 0
  fi
  [[ "$key" =~ $KEY_RE ]] || { echo "Formato da chave de inscricao invalido." >&2; return 2; }
  [[ "$panel" =~ $PANEL_RE ]] || { echo "URL do painel de inscricao invalida." >&2; return 2; }
  # os valores ja foram validados acima: so ha caracteres sem escape em JSON
  ( umask 077; printf '{"v":1,"painel":"%s","chave":"%s"}' "${panel%/}" "$key" > "$out" )
  echo "Inscricao global preparada ($(basename -- "$out"))."
}

incorporar() {
  local deb=${1:?Informe o .deb} json=${2:?Informe o inscricao.json}
  [[ -f "$deb" && "$deb" == *.deb ]] || { echo "Pacote .deb invalido." >&2; return 2; }
  if [[ ! -f "$json" ]]; then
    echo "::warning title=Pacote sem inscricao automatica::inscricao.json ausente; $(basename -- "$deb") sera mantido sem inscricao."
    return 0
  fi
  local content
  content=$(cat -- "$json")
  [[ "$content" =~ ^\{\"v\":1,\"painel\":\"https?://[^\"]+\",\"chave\":\"(nx1\.[0-9]{1,12}\.[A-Za-z0-9_-]{16,128}|nx2\.[0-9]{1,10}\.[0-9]{1,12}\.[0-9a-f]{64})\"\}$ ]] \
    || { echo "inscricao.json com formato inesperado." >&2; return 2; }
  TMP_DIR=$(mktemp -d)
  local tmp=$TMP_DIR
  dpkg-deb -R "$deb" "$tmp/root"
  if [[ ! -f "$tmp/root$DEST_DIR/$COORDINATOR" ]]; then
    echo "::warning title=Pacote sem inscricao automatica::$(basename -- "$deb") nao contem o coordenador Nextec; inscricao.json nao sera instalado."
    return 0
  fi
  install -d -m 0755 "$tmp/root$DEST_DIR"
  install -m 0600 -- "$json" "$tmp/root$DEST_DIR/$DEST_NAME"
  dpkg-deb -Zxz --build --root-owner-group "$tmp/root" "$tmp/novo.deb"
  mv -- "$tmp/novo.deb" "$deb"
  echo "Inscricao global incorporada ao pacote ($DEST_DIR/$DEST_NAME, root:root 0600)."
}

case "${1:-}" in
  gerar) shift; gerar "$@" ;;
  incorporar) shift; incorporar "$@" ;;
  *) echo "Uso: $0 gerar <saida.json> | incorporar <pacote.deb> <inscricao.json>" >&2; exit 2 ;;
esac
