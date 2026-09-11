#!/bin/sh
set -eu

case "$(uname -m)" in
  aarch64|arm64) ads_arch=arm64 ;;
  x86_64|amd64) ads_arch=x86_64 ;;
  *) echo "snyk-ads: unsupported architecture" >&2; exit 1 ;;
esac

find_component() {
  for candidate in "$HOME/.ads-scan/bin/snyk-$1-linux-$ads_arch" \
                   "$HOME/.ads-scan/bin/snyk-$1"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if [ "$1" = scan ] && [ -x "$HOME/.ads-scan/bin/snyk-agent-scan" ]; then
    printf '%s\n' "$HOME/.ads-scan/bin/snyk-agent-scan"
    return 0
  fi
  return 1
}

case "${1:-report}" in
  scan)
    find_component scan || command -v snyk-agent-scan || command -v snyk-scan
    ;;
  report)
    echo "snyk-ads: component binaries after installation"
    for component in scan guard studio-installer; do
      case "$component" in
        scan) label=Scan ;;
        guard) label=Guard ;;
        studio-installer) label=Studio ;;
      esac
      if binary="$(find_component "$component")"; then
        echo "snyk-ads: $label: downloaded ($binary)"
      else
        echo "snyk-ads: $label: not downloaded; may be disabled in Evo settings"
      fi
    done
    ;;
  *) echo "snyk-ads: expected report or scan" >&2; exit 1 ;;
esac
