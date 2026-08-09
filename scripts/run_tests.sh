#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_src="$repo_root/_test"

if [[ ! -d "$test_src" ]]; then
  echo "missing test directory: $test_src" >&2
  exit 1
fi

copied=()
cleanup() {
  for path in "${copied[@]}"; do
    rm -f "$path"
  done
}
trap cleanup EXIT

for src in "$test_src"/*_test.go; do
  [[ -e "$src" ]] || continue
  dst="$repo_root/$(basename "$src")"
  if [[ -e "$dst" ]]; then
    echo "refusing to overwrite existing root test file: $dst" >&2
    exit 1
  fi
  cp "$src" "$dst"
  copied+=("$dst")
done

if [[ ${#copied[@]} -eq 0 ]]; then
  echo "no test files found in $test_src" >&2
  exit 1
fi

GOCACHE="${GOCACHE:-/tmp/ldaphelp-gocache}" go test "$@" ./...
