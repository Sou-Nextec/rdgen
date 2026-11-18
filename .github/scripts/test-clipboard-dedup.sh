#!/usr/bin/env bash
# Teste de regressao do patch de deduplicacao da area de transferencia (eco do host regravando o clipboard).
#  1. testes unitarios do modulo (rustc --test, so std, Rust 1.75 como o RustDesk);
#  2. clipboardDedup.diff aplica no RustDesk 1.5.0 (git apply --check);
#  3. o script usado pelos workflows aplica o patch e liga o modulo em lib.rs e clipboard.rs;
#  4. o diff mexe so em src/lib.rs e src/clipboard.rs;
#  5. aplicar de novo em 1.5.0 falha (patch quebrado nao passa em silencio).
# Nao compila o RustDesk inteiro: a ligacao em clipboard.rs so e conferida por aplicacao e leitura do diff.
set -euo pipefail

raiz=$(cd "$(dirname "$0")/../.." && pwd)
patches="$raiz/.github/patches"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
RUSTC=${RUSTC:-rustc}

echo "== 1. testes do modulo"
"$RUSTC" --version
"$RUSTC" --edition 2021 -D warnings --test "$patches/nextec_clipboard_dedup.rs" -o "$tmp/dedup_test"
"$tmp/dedup_test"

echo "== 2. git apply --check no RustDesk 1.5.0"
git clone --quiet --depth 1 --branch 1.5.0 --no-recurse-submodules https://github.com/rustdesk/rustdesk.git "$tmp/rustdesk"
git -C "$tmp/rustdesk" apply --check "$patches/clipboardDedup.diff"

echo "== 3. script de aplicacao dos workflows"
pwsh -NoProfile -File "$raiz/.github/scripts/apply-clipboard-dedup.ps1" -Fonte "$patches" -Versao 1.5.0 -Rustdesk "$tmp/rustdesk"
cmp "$patches/nextec_clipboard_dedup.rs" "$tmp/rustdesk/src/nextec_clipboard_dedup.rs"
grep -q '^mod nextec_clipboard_dedup;$' "$tmp/rustdesk/src/lib.rs"
grep -q 'nextec_clipboard_dedup::deve_aplicar' "$tmp/rustdesk/src/clipboard.rs"
grep -q 'nextec_clipboard_dedup::enviado' "$tmp/rustdesk/src/clipboard.rs"

echo "== 4. diff so em lib.rs e clipboard.rs"
alterados=$(grep '^diff --git' "$patches/clipboardDedup.diff" | sed 's|^diff --git a/\(.*\) b/.*|\1|' | sort | tr '\n' ' ')
[ "$alterados" = "src/clipboard.rs src/lib.rs " ] || { echo "arquivos no diff: $alterados"; exit 1; }

echo "== 5. patch ja aplicado nao passa em silencio em 1.5.0"
if pwsh -NoProfile -File "$raiz/.github/scripts/apply-clipboard-dedup.ps1" -Fonte "$patches" -Versao 1.5.0 -Rustdesk "$tmp/rustdesk" >/dev/null 2>&1; then
  echo "esperava falha ao reaplicar em 1.5.0"; exit 1
fi

echo "OK"
