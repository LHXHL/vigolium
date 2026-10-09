#!/usr/bin/env bash
# Gate a release dist directory BEFORE anything is uploaded to the CDN.
#
# `make release` and `make public-release` call this between building and the
# first `mc cp`. It is entirely local (no network) and fails on any miss, so a
# half-built or stale dist dir never reaches R2. The installers resolve the
# version from metadata.json first, then download that version's archive and
# look its digest up in checksums.txt, so every one of those three must agree
# before the upload starts.
#
# Checks:
#   1. exactly one archive per release target, named
#      vigolium_<version>_<os>_<arch>.tar.gz (.zip for windows) - the name is
#      what proves which version was built (see NPM_NEEDS_BUILD in the
#      Makefile for why grepping the binary is not used)
#   2. no other vigolium_* archive in the dir (count == targets)
#   3. checksums.txt lists every archive, and every line names a file that
#      exists in the dir
#   4. `sha256 -c checksums.txt` passes
#   5. metadata.json "version" == the release version
#   6. any extra required upload files exist (REQUIRE)
#
# Usage (normally via `make release-verify`):
#   release-verify.sh <dist-dir>
#
# Env / make vars:
#   VERSION  = release version as stamped in metadata.json (e.g. v0.5.2)
#   TARGETS  = space-separated goos/goarch list (Makefile PUBLIC_TARGETS)
#   REQUIRE  = extra files that must exist before upload (optional)
set -euo pipefail

dist="${1:?usage: release-verify.sh <dist-dir>}"
VERSION="${VERSION:?VERSION is required (e.g. v0.5.2)}"
TARGETS="${TARGETS:?TARGETS is required (e.g. \"linux/amd64 darwin/arm64\")}"
REQUIRE="${REQUIRE:-}"

ver_no_v="${VERSION#v}"
errors=0
fail() { printf '\033[31m[!] release-verify: %s\033[0m\n' "$*" >&2; errors=$((errors + 1)); }
info() { printf '\033[36m[*]\033[0m release-verify: %s\n' "$*"; }

[ -d "$dist" ] || { fail "dist dir not found: $dist"; exit 1; }

# --- 1. one correctly-versioned archive per target ---------------------------
expected=()
for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext="tar.gz"
  [ "$goos" = "windows" ] && ext="zip"
  name="vigolium_${ver_no_v}_${goos}_${goarch}.${ext}"
  expected+=("$name")
  if [ ! -s "$dist/$name" ]; then
    fail "missing or empty archive for $target: $dist/$name"
  fi
done

# --- 2. nothing extra (a stale archive from another version would be uploaded)
actual=()
while IFS= read -r f; do
  [ -n "$f" ] && actual+=("$(basename "$f")")
done < <(find "$dist" -maxdepth 1 -type f \( -name 'vigolium_*.tar.gz' -o -name 'vigolium_*.zip' \) | sort)
if [ "${#actual[@]}" -ne "${#expected[@]}" ]; then
  fail "expected ${#expected[@]} archives for [$TARGETS], found ${#actual[@]}: ${actual[*]:-none}"
fi
for f in ${actual[@]+"${actual[@]}"}; do
  case " ${expected[*]} " in
    *" $f "*) ;;
    *) fail "unexpected archive (wrong version or target?): $f" ;;
  esac
done

# --- 3 + 4. checksums.txt covers exactly what exists, and verifies -----------
checksums="$dist/checksums.txt"
if [ ! -s "$checksums" ]; then
  fail "missing or empty $checksums"
else
  listed=()
  while read -r _sum name; do
    [ -n "${name:-}" ] || continue
    name="${name#\*}" # binary-mode marker from sha256sum -b
    listed+=("$name")
    [ -f "$dist/$name" ] || fail "checksums.txt lists $name but it is not in $dist"
  done < "$checksums"
  for name in "${expected[@]}"; do
    case " ${listed[*]:-} " in
      *" $name "*) ;;
      *) fail "checksums.txt does not list $name" ;;
    esac
  done
  if command -v shasum >/dev/null 2>&1; then
    sha_check=(shasum -a 256 -c)
  else
    sha_check=(sha256sum -c)
  fi
  # Print only the failing lines; the OK ones are noise.
  if ! sha_out="$(cd "$dist" && "${sha_check[@]}" checksums.txt 2>&1)"; then
    printf '%s\n' "$sha_out" | grep -v ': OK$' >&2 || true
    fail "checksum mismatch: (cd $dist && ${sha_check[*]} checksums.txt)"
  fi
fi

# --- 5. version pointer matches ------------------------------------------------
metadata="$dist/metadata.json"
if [ ! -s "$metadata" ]; then
  fail "missing or empty $metadata"
else
  meta_version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$metadata" | head -1)"
  if [ "$meta_version" != "$VERSION" ]; then
    fail "metadata.json version is '${meta_version:-<none>}', expected '$VERSION'"
  fi
fi

# --- 6. extra upload files ------------------------------------------------------
for f in $REQUIRE; do
  [ -s "$f" ] || fail "missing required upload artifact: $f"
done

if [ "$errors" -gt 0 ]; then
  printf '\033[31m[!] release-verify: %d problem(s) in %s; nothing was uploaded.\033[0m\n' "$errors" "$dist" >&2
  exit 1
fi
info "$dist OK: ${#expected[@]} archives for $VERSION, checksums verified, metadata.json matches"
