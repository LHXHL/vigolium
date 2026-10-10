#!/usr/bin/env bash
# Prune old release archives from an R2 prefix AFTER a successful upload.
#
# Replaces the old up-front `mc rm --recursive --force <prefix>/ || true`,
# which emptied the CDN before the new build was uploaded: any failure between
# the wipe and the last `mc cp` left installers with no binaries at all. Now
# `make release` uploads first (version pointer last) and only then calls this.
#
# Deletes ONLY objects that are all of:
#   - named vigolium_<version>_<os>_<arch>.tar.gz|.zip (so install.sh,
#     bootstrap.sh, metadata.json, checksums.txt and anything else are never
#     touched)
#   - not listed in the new <dist>/checksums.txt
#   - not one of the KEEP most recently uploaded versions (rollback window;
#     the version being released always counts as one of them)
#
# "Most recent" is the newest lastModified among a version's archives, so the
# window follows upload order rather than version-string sorting (which gets
# prereleases like 0.5.0-alpha vs 0.5.0 wrong).
#
# Usage (normally via `make release-prune`):
#   release-prune.sh <r2-dir> <dist-dir>
#
# Env / make vars:
#   KEEP     = number of versions to keep (default 3)
#   DRY_RUN  = 1 to print what would be deleted without deleting
#   MC       = mc binary (default: mc)
set -euo pipefail

r2_dir="${1:?usage: release-prune.sh <r2-dir> <dist-dir>}"
dist="${2:?usage: release-prune.sh <r2-dir> <dist-dir>}"
KEEP="${KEEP:-3}"
DRY_RUN="${DRY_RUN:-}"
MC="${MC:-mc}"
r2_dir="${r2_dir%/}"

die()  { printf '\033[31m[!] release-prune: %s\033[0m\n' "$*" >&2; exit 1; }
info() { printf '\033[36m[*]\033[0m release-prune: %s\n' "$*"; }

case "$KEEP" in ''|*[!0-9]*) die "KEEP must be a positive integer, got '$KEEP'" ;; esac
[ "$KEEP" -ge 1 ] || die "KEEP must be >= 1"
checksums="$dist/checksums.txt"
[ -s "$checksums" ] || die "missing $checksums; refusing to prune without the new release manifest"

# archive name -> version ("" for anything that is not a release archive)
archive_version() {
  printf '%s\n' "$1" | sed -n -E 's/^vigolium_(.+)_[^_]+_[^_]+\.(tar\.gz|zip)$/\1/p'
}

# Versions published by this release (normally exactly one).
current_names=" "
current_versions=" "
while read -r _sum name; do
  [ -n "${name:-}" ] || continue
  name="${name#\*}"
  current_names="$current_names$name "
  v="$(archive_version "$name")"
  [ -n "$v" ] || continue
  case "$current_versions" in *" $v "*) ;; *) current_versions="$current_versions$v " ;; esac
done < "$checksums"
[ "$current_versions" != " " ] || die "$checksums lists no vigolium_* archives; refusing to prune"

listing="$(mktemp)"
trap 'rm -f "$listing"' EXIT
"$MC" ls --json "$r2_dir/" > "$listing" || die "could not list $r2_dir"

# "<lastModified>\t<key>" for every file object (mc ls --json prints one JSON
# object per line; fields are extracted independently of their order).
objects="$(
  grep '"type":"file"' "$listing" | while IFS= read -r line; do
    key="$(printf '%s\n' "$line" | sed -n -E 's/.*"key":"([^"]*)".*/\1/p')"
    ts="$(printf '%s\n' "$line" | sed -n -E 's/.*"lastModified":"([^"]*)".*/\1/p')"
    [ -n "$key" ] && printf '%s\t%s\n' "${ts:--}" "$key"
  done
)" || true

# Rollback window: the versions in this release, then the most recently
# uploaded other versions until KEEP versions are held.
ncurrent="$(printf '%s\n' $current_versions | wc -l | tr -d ' ')"
older="$(
  printf '%s\n' "$objects" | while IFS="$(printf '\t')" read -r ts key; do
    [ -n "${key:-}" ] || continue
    v="$(archive_version "$key")"
    [ -n "$v" ] || continue
    case "$current_versions" in (*" $v "*) continue ;; esac
    printf '%s\t%s\n' "$ts" "$v"
  done | LC_ALL=C sort -r | awk -F '\t' '!seen[$2]++ { print $2 }'
)"
keep_versions="$current_versions"
if [ "$KEEP" -gt "$ncurrent" ] && [ -n "$older" ]; then
  keep_versions="$keep_versions$(printf '%s\n' "$older" | head -n "$((KEEP - ncurrent))" | tr '\n' ' ')"
fi
info "keeping versions:$keep_versions(KEEP=$KEEP)"

deleted=0
failed=0
while IFS="$(printf '\t')" read -r _ts key; do
  [ -n "${key:-}" ] || continue
  v="$(archive_version "$key")"
  [ -n "$v" ] || continue
  case "$current_names" in *" $key "*) continue ;; esac
  case "$keep_versions" in *" $v "*) continue ;; esac
  if [ -n "$DRY_RUN" ]; then
    info "would delete $r2_dir/$key"
  elif "$MC" rm "$r2_dir/$key"; then
    deleted=$((deleted + 1))
  else
    printf '\033[33m[!] release-prune: failed to delete %s\033[0m\n' "$r2_dir/$key" >&2
    failed=$((failed + 1))
  fi
done <<EOF
$objects
EOF

info "deleted $deleted old archive(s) from $r2_dir"
[ "$failed" -eq 0 ] || die "$failed delete(s) failed"
