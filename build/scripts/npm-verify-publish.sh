#!/usr/bin/env bash
set -euo pipefail

# Verify that an npm publish actually landed on the registry.
#
# Why this exists: registry.npmjs.org answers a publish with `202 Accepted`,
# not `201 Created`. The tarball is queued and processed asynchronously, so
# `npm publish` exits 0 while the version does not exist yet - and sometimes
# never does. On the 0.4.6 release three of the five platform packages
# (darwin-arm64, linux-arm64, windows-x64) each got a clean 202 and silently
# never appeared, leaving @vigolium/vigolium@0.4.6 pointing at
# optionalDependencies that 404. `npm i -g` then succeeds and the launcher
# fails at first run. Exit code alone is not proof of publication; only a
# read-back from the registry is.
#
# Both checks hit registry.npmjs.org directly with curl rather than going
# through npm: `npm view` / `npm dist-tag ls` consult ~/.npm/_cacache first and
# `--prefer-online` only defeats that local cache, not the registry's own edge
# cache.
#
# Usage (normally via `make npm-publish`):
#   npm-verify-publish.sh version  <package> <version>       # version exists
#   npm-verify-publish.sh dist-tag <package> <tag> <version> # tag resolves
#
# Env:
#   NPM_VERIFY_TRIES = poll attempts (default 30)
#   NPM_VERIFY_SLEEP = seconds between attempts (default 10)

MODE="${1:?usage: npm-verify-publish.sh version|dist-tag ...}"
PKG="${2:?package name required}"

TRIES="${NPM_VERIFY_TRIES:-30}"
SLEEP="${NPM_VERIFY_SLEEP:-10}"

# Registry paths take the scope separator escaped: @scope%2fname.
PKG_PATH="${PKG/\//%2f}"

RED='\033[31m'
RESET='\033[0m'

note() { printf '[*]     %s\n' "$1"; }
fail() { printf "${RED}[!] %s${RESET}\n" "$1" >&2; exit 1; }

case "$MODE" in
version)
	VERSION="${3:?version required}"
	for i in $(seq 1 "$TRIES"); do
		code=$(curl -sS -o /dev/null -w '%{http_code}' \
			-H 'Cache-Control: no-cache' \
			"https://registry.npmjs.org/${PKG}/${VERSION}?cb=$(date +%s)" 2>/dev/null || true)
		[ "$code" = "200" ] && { note "confirmed on registry: ${PKG}@${VERSION}"; exit 0; }
		[ "$i" = "$TRIES" ] && break
		note "${PKG}@${VERSION} not on registry yet (HTTP $code) - attempt $i/$TRIES, retrying in ${SLEEP}s"
		sleep "$SLEEP"
	done
	fail "${PKG}@${VERSION} never appeared after $((TRIES * SLEEP))s.
    The registry accepted the upload (202) but did not finish processing it.
    Re-run 'make npm-publish' - the version is not taken, so the republish
    will be accepted. Do NOT bump the version for this."
	;;
dist-tag)
	TAG="${3:?tag required}"
	VERSION="${4:?version required}"
	for i in $(seq 1 "$TRIES"); do
		resolved=$(curl -fsS -H 'Cache-Control: no-cache' \
			"https://registry.npmjs.org/-/package/${PKG_PATH}/dist-tags" 2>/dev/null \
			| sed -n "s/.*\"${TAG}\":\"\([^\"]*\)\".*/\1/p" || true)
		[ "$resolved" = "$VERSION" ] && { note "confirmed: ${TAG} -> ${resolved}"; exit 0; }
		[ "$i" = "$TRIES" ] && break
		note "${TAG} still '${resolved:-<unset>}' - attempt $i/$TRIES, retrying in ${SLEEP}s"
		sleep "$SLEEP"
	done
	fail "${TAG} resolved to '${resolved:-<unset>}', expected '${VERSION}' after $((TRIES * SLEEP))s.
    Re-point it manually: npm dist-tag add ${PKG}@${VERSION} ${TAG}"
	;;
*)
	fail "unknown mode '$MODE' (expected 'version' or 'dist-tag')"
	;;
esac
