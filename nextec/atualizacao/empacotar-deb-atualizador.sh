#!/usr/bin/env bash
set -euo pipefail

deb=${1:?Informe o .deb gerado}
updater_dir=${2:?Informe a pasta nextec/atualizacao}
[[ -f "$deb" && "$deb" == *.deb ]]
app_name=${3:-Nextec-Connect}
package_version=${4:-${package_version:-}}
[[ -z "$package_version" || "$package_version" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo "Versão do pacote inválida." >&2; exit 2; }
# O nome do app e livre (qualquer um); so precisa ser seguro para JSON e nome de arquivo. A inclusao do agente
# e decidida pelo flag nx_agent do build, nunca pelo nome.
[[ "$app_name" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "Nome do app inválido." >&2; exit 2; }

tmp=$(mktemp -d)
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT
dpkg-deb -R "$deb" "$tmp/root"
pkg=$(dpkg-deb -f "$deb" Package)
arch=$(dpkg-deb -f "$deb" Architecture)
# Debian package names are lowercase; the generator's display name is not.
pkg=$(printf '%s' "$pkg" | tr '[:upper:]' '[:lower:]')
[[ "$pkg" =~ ^[a-z0-9][a-z0-9+.-]+$ ]]
sed -i "s/^Package:.*/Package: $pkg/" "$tmp/root/DEBIAN/control"
if [[ -n "$package_version" ]]; then sed -i "s/^Version:.*/Version: $package_version/" "$tmp/root/DEBIAN/control"; fi
[[ "$arch" == amd64 || "$arch" == arm64 ]]

install -d -m 0755 "$tmp/root/usr/lib/nextec-connect" "$tmp/root/usr/lib/systemd/system"
sed "s/__PACKAGE_NAME__/$pkg/g" "$updater_dir/atualizador-linux.py" > "$tmp/root/usr/lib/nextec-connect/atualizador-linux.py"
install -m 0755 "$updater_dir/agente-senha-linux.py" "$tmp/root/usr/lib/nextec-connect/agente-senha-linux.py"
install -m 0755 "$updater_dir/coordenador-agente-nextec-linux.py" "$tmp/root/usr/lib/nextec-connect/coordenador-agente-nextec-linux.py"
install -m 0644 "$updater_dir/nextec-agent-bootstrap.service" "$tmp/root/usr/lib/systemd/system/nextec-agent-bootstrap.service"
install -m 0644 "$updater_dir/nextec-agent-bootstrap.timer" "$tmp/root/usr/lib/systemd/system/nextec-agent-bootstrap.timer"
install -m 0644 "$updater_dir/nextec-connect-update.service" "$tmp/root/usr/lib/systemd/system/nextec-connect-update.service"
install -m 0644 "$updater_dir/nextec-connect-update.timer" "$tmp/root/usr/lib/systemd/system/nextec-connect-update.timer"
install -m 0644 "$updater_dir/nextec-connect-agent.service" "$tmp/root/usr/lib/systemd/system/nextec-connect-agent.service"
install -m 0644 "$updater_dir/nextec-connect-agent.timer" "$tmp/root/usr/lib/systemd/system/nextec-connect-agent.timer"
chmod 0755 "$tmp/root/usr/lib/nextec-connect/atualizador-linux.py"
# Marcador de instalacao independente do nome do app (lido por Coordenar/Provisionar/atualizador, se precisarem).
# No DEB o equivalente do upgrade_code do MSI e o nome do pacote.
printf '{"v":1,"app":"%s","upgrade_code":"%s"}' "$app_name" "$pkg" > "$tmp/root/usr/lib/nextec-connect/nextec-marker.json"
chmod 0644 "$tmp/root/usr/lib/nextec-connect/nextec-marker.json"

control="$tmp/root/DEBIAN/control"
if [[ -f "$control" ]] && ! grep -qiE '^Depends:.*(^|[, ])python3([, ]|$)' "$control"; then
  if grep -q '^Depends:' "$control"; then
    sed -i '/^Depends:/ s/$/, python3/' "$control"
  else
    awk 'BEGIN { done=0 } /^$/ && !done { print "Depends: python3"; done=1 } { print } END { if (!done) print "Depends: python3" }' "$control" > "$control.tmp"
    mv "$control.tmp" "$control"
  fi
fi

insert_hook() {
  local file=$1 marker=$2 hook=$3 content
  [[ -f "$file" ]] || printf '#!/bin/sh\nset -e\n' > "$file"
  if grep -qF "$marker" "$file"; then return; fi
  content=$(cat "$file")
  if grep -qE '^exit 0$' "$file"; then
    awk -v hook="$hook" '{ lines[NR]=$0; if ($0 == "exit 0") last=NR } END { for (i=1; i<=NR; i++) { if (i == last) print hook; print lines[i] } if (!last) print hook }' "$file" > "$file.tmp"
    mv "$file.tmp" "$file"
  else
    printf '\n%s\n' "$hook" >> "$file"
  fi
  chmod 0755 "$file"
}

insert_hook "$tmp/root/DEBIAN/postinst" 'nextec-connect-update.timer' 'if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; systemctl enable --now nextec-connect-update.timer || true; fi'
insert_hook "$tmp/root/DEBIAN/postinst" 'nextec-connect-agent.timer' 'if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; systemctl enable nextec-connect-agent.timer || true; fi'
insert_hook "$tmp/root/DEBIAN/postinst" 'nextec-agent-bootstrap.timer' 'if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; systemctl enable --now nextec-agent-bootstrap.timer || true; fi'
insert_hook "$tmp/root/DEBIAN/prerm" 'nextec-connect-update.timer' 'if [ "$1" = remove ] && [ -d /run/systemd/system ]; then systemctl disable --now nextec-connect-update.timer || true; fi'
insert_hook "$tmp/root/DEBIAN/prerm" 'nextec-connect-agent.timer' 'if [ "$1" = remove ] && [ -d /run/systemd/system ]; then systemctl disable --now nextec-connect-agent.timer nextec-connect-agent.service || true; fi'
insert_hook "$tmp/root/DEBIAN/prerm" 'nextec-agent-bootstrap.timer' 'if [ "$1" = remove ] && [ -d /run/systemd/system ]; then systemctl disable --now nextec-agent-bootstrap.timer nextec-agent-bootstrap.service || true; fi'

rebuilt="$tmp/rebuilt.deb"
dpkg-deb -Zxz --build --root-owner-group "$tmp/root" "$rebuilt"
mv -- "$rebuilt" "$deb"
echo "Atualizador e agente Linux condicionado adicionados: $deb ($pkg/$arch)"
