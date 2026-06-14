#!/usr/bin/env sh
# Install the secrets-guard CLI to a user-level bin directory (default
# ~/.local/bin) so it is available on your shell PATH for running apps with
# vault references (secrets-guard run / read). No administrator privileges needed.
#
# Usage:
#   ./install.sh                 # install to ~/.local/bin
#   ./install.sh --dir /opt/homebrew/bin   # or any writable dir already on PATH
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/plugins/secrets-guard/bin"

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin) o=darwin ;;
  Linux)  o=linux ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac
case "$arch" in
  arm64|aarch64) a=arm64 ;;
  x86_64|amd64)  a=amd64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

src="$BIN/secrets-guard-$o-$a"
[ -x "$src" ] || { echo "binary not found: $src (build it with: cd src && go build ...)" >&2; exit 1; }

exec "$src" install "$@"
