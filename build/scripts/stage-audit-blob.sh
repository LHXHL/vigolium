#!/usr/bin/env bash
# Stage the matching vigolium-audit blob into the go:embed path before a
# cross-compiled vigolium build.
#
# goreleaser invokes this as a per-target build pre-hook:
#     stage-audit-blob.sh <goos> <goarch>
#
# The blob is zstd-compressed by internal/tools/blobpack into
# pkg/audit/bin/_bin/vigolium-audit.zst plus its pin vigolium-audit.pin (sha256
# and size of the UNCOMPRESSED executable, and its platform). The raw
# executable is never left in _bin: `go:embed all:_bin` would embed it too.
#
# The embed path is SHARED by every target, so cross builds MUST run
# sequentially (goreleaser -p 1) — parallel builds would race on it and bake
# the wrong-arch blob into a binary. blobpack refuses a blob whose header does
# not match <goos>/<goarch>, and the runtime refuses a pin for another
# platform.
#
#     stage-audit-blob.sh --pins <asset-dir>
#
# instead generates pkg/audit/bin/pins_gen.go for the opt-in `audit_external`
# build from every dist blob and writes the download assets
# <asset-dir>/vigolium-audit_<sha12>_<os>_<arch>.zst to upload to the
# VIGOLIUM_AUDIT_BASE_URL host.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
dist="$repo_root/platform/vigolium-audit/build/dist"

if [ "${1:-}" = "--pins" ]; then
  asset_dir="${2:?usage: stage-audit-blob.sh --pins <asset-dir>}"
  case "$asset_dir" in /*) ;; *) asset_dir="$repo_root/$asset_dir" ;; esac
  args=()
  for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    t_os="${target%/*}"; t_arch="${target#*/}"
    blob="$dist/vigolium-audit-$t_os-${t_arch/amd64/x64}"
    [ "$t_os" = "windows" ] && blob="$blob.exe"
    if [ ! -f "$blob" ]; then
      echo "[stage-audit-blob] missing audit blob: $blob (run 'make update-audit')" >&2
      exit 1
    fi
    args+=("$target=$blob")
  done
  mkdir -p "$asset_dir"
  # Keep the generated assets out of git without touching the root .gitignore.
  printf '*\n' > "$asset_dir/.gitignore"
  (cd "$repo_root" && go run ./internal/tools/blobpack pins -name vigolium-audit \
    -go-out pkg/audit/bin/pins_gen.go -asset-dir "$asset_dir" "${args[@]}")
  exit 0
fi

goos="${1:?usage: stage-audit-blob.sh <goos> <goarch>}"
goarch="${2:?usage: stage-audit-blob.sh <goos> <goarch>}"

# Map Go arch names to the vigolium-audit blob naming (amd64 -> x64).
case "$goarch" in
  amd64) blob_arch="x64" ;;
  arm64) blob_arch="arm64" ;;
  *) echo "[stage-audit-blob] unsupported goarch: $goarch" >&2; exit 1 ;;
esac

# Bun emits the windows target with an .exe suffix. The destination name stays
# extensionless for every target because it is a fixed go:embed path
# (pkg/audit/bin/embed.go); the extractor re-adds .exe at runtime on Windows.
blob_ext=""
if [ "$goos" = "windows" ]; then
  blob_ext=".exe"
  if [ "$goarch" != "amd64" ]; then
    echo "[stage-audit-blob] windows/$goarch is not a supported target -- Bun has no" >&2
    echo "  bun-windows-arm64 compile target, so no audit blob exists for it." >&2
    exit 1
  fi
fi

src="$dist/vigolium-audit-$goos-$blob_arch$blob_ext"
dst="$repo_root/pkg/audit/bin/_bin/vigolium-audit"

if [ ! -f "$src" ]; then
  echo "[stage-audit-blob] missing audit blob: $src" >&2
  echo "  run 'make update-audit' to build the cross-compile blobs first." >&2
  exit 1
fi

# Sanity: confirm the blob's container format matches the requested target
# before embedding it. Catches a mislabeled or corrupt dist artifact.
desc="$(file -b "$src")"
case "$goos" in
  linux)
    echo "$desc" | grep -q "ELF" || {
      echo "[stage-audit-blob] $src is not an ELF binary (got: $desc)" >&2; exit 1; } ;;
  darwin)
    echo "$desc" | grep -q "Mach-O" || {
      echo "[stage-audit-blob] $src is not a Mach-O binary (got: $desc)" >&2; exit 1; } ;;
  windows)
    echo "$desc" | grep -q "PE32" || {
      echo "[stage-audit-blob] $src is not a PE binary (got: $desc)" >&2; exit 1; } ;;
esac

# The container check above passes a same-OS, wrong-ARCH blob (linux x64 and
# linux arm64 are both "ELF"; darwin x64 and arm64 are both "Mach-O"), which
# would embed silently. Assert the machine type too, so a mislabeled dist
# artifact is caught here at the point of the mistake rather than downstream.
case "$goarch" in
  amd64) arch_re="x86[-_]64" ;;
  arm64) arch_re="aarch64|arm64" ;;
esac
echo "$desc" | grep -qE "$arch_re" || {
  echo "[stage-audit-blob] $src is not a $goarch binary (got: $desc)" >&2
  echo "  the dist artifact is mislabeled -- rebuild with 'make update-audit'." >&2
  exit 1; }

mkdir -p "$(dirname "$dst")"
# Remove a raw blob left by a pre-compression checkout so it is not embedded.
rm -f "$dst"
(cd "$repo_root" && go run ./internal/tools/blobpack -in "$src" -out "$dst" -platform "$goos/$goarch")
echo "[stage-audit-blob] staged vigolium-audit-$goos-$blob_arch$blob_ext -> _bin/vigolium-audit.zst ($desc)"
