#!/usr/bin/env node
// Stage the @vigolium/vigolium npm packages.
//
// Produces, under build/dist-npm/:
//   - vigolium/              the thin launcher package (@vigolium/vigolium@<v>)
//   - vigolium-<tag>/        4 platform packages (@vigolium/vigolium@<v>-<tag>)
//                            each carrying the gzipped binary in vendor/<tag>/
//
// The binary is gzipped so each platform package's *unpacked* size stays at
// ~70-110MB instead of 200-310MB, keeping it under npm's per-version ceiling.
// bin/vigolium.js decompresses it once on first run.
//
// Source binaries come from goreleaser output in build/dist/
// (vigolium_<goos>_<goarch>_<variant>/vigolium). Run `make snapshot` first.
//
// Usage:
//   node build/npm/build.mjs [--pack] [--allow-missing=<tag,tag>]
//   VIGOLIUM_VERSION=0.1.2-alpha node build/npm/build.mjs

import { spawnSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  readdirSync,
  readFileSync,
  rmSync,
  mkdirSync,
  copyFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGzip } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DIST_DIR = path.join(REPO_ROOT, "build", "dist");
const OUT_DIR = path.join(REPO_ROOT, "build", "dist-npm");
const LAUNCHER_SRC = path.join(__dirname, "bin", "vigolium.js");
// Bundle the full project README onto the npm package page.
const README_SRC = path.join(REPO_ROOT, "README.md");
const LICENSE_SRC = path.join(REPO_ROOT, "LICENSE");
const VERSION_GO = path.join(REPO_ROOT, "pkg", "cli", "version.go");

const NPM_NAME = "@vigolium/vigolium";
const LICENSE_ID = "MIT";
const HOMEPAGE = "https://vigolium.com";
const DESCRIPTION = "Vigolium - High-fidelity vulnerability scanner fusing agentic AI with native speed, modularity, and precision";
const KEYWORDS = [
  "vigolium",
  "security",
  "security-scanner",
  "vulnerability",
  "vulnerability-scanner",
  "dast",
  "ai-powered-scanner",
];
const REPOSITORY = {
  type: "git",
  url: "git+https://github.com/vigolium/vigolium.git",
};
const ENGINES = { node: ">=16" };

// windows is x64-only, matching the shipped matrix in .goreleaser.yaml: the
// embedded vigolium-audit and jstangle helpers are `bun build --compile`
// outputs and Bun has no bun-windows-arm64 target. Windows on ARM installs the
// x64 package and runs it under emulation.
const PLATFORMS = [
  { tag: "linux-x64", goos: "linux", goarch: "amd64", os: "linux", cpu: "x64" },
  { tag: "linux-arm64", goos: "linux", goarch: "arm64", os: "linux", cpu: "arm64" },
  { tag: "darwin-x64", goos: "darwin", goarch: "amd64", os: "darwin", cpu: "x64" },
  { tag: "darwin-arm64", goos: "darwin", goarch: "arm64", os: "darwin", cpu: "arm64" },
  { tag: "windows-x64", goos: "windows", goarch: "amd64", os: "win32", cpu: "x64" },
];

// The file name goreleaser gives the built binary, per GOOS.
function binaryNameFor(goos) {
  return goos === "windows" ? "vigolium.exe" : "vigolium";
}

const args = process.argv.slice(2);
const doPack = args.includes("--pack");
const allowMissing = new Set(
  (args.find((a) => a.startsWith("--allow-missing=")) || "")
    .split("=")[1]
    ?.split(",")
    .map((s) => s.trim())
    .filter(Boolean) || [],
);

function fail(msg) {
  console.error(`\x1b[31m[!] ${msg}\x1b[0m`);
  process.exit(1);
}

function info(msg) {
  console.log(`\x1b[36m[*]\x1b[0m ${msg}`);
}

// --- version --------------------------------------------------------------

function deriveBaseVersion() {
  if (process.env.VIGOLIUM_VERSION) {
    return process.env.VIGOLIUM_VERSION.replace(/^v/, "");
  }
  const src = readFileSync(VERSION_GO, "utf8");
  const m = src.match(/^\s*Version\s*=\s*"v?([^"]+)"/m);
  if (!m) fail(`Could not parse Version from ${VERSION_GO}`);
  return m[1];
}

const baseVersion = deriveBaseVersion();
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(baseVersion)) {
  console.warn(
    `\x1b[33m[warn] "${baseVersion}" does not look like a semver string; npm may reject it.\x1b[0m`,
  );
}
const platformVersion = (tag) => `${baseVersion}-${tag}`;

// --- built-version verification -------------------------------------------

// goreleaser names each archive `vigolium_<version>_<os>_<arch>.tar.gz` from the
// version it actually built (archives.name_template in .goreleaser.yaml), and
// `--clean` wipes build/dist at the start of every run — so the archive version
// is an authoritative, embed-string-proof record of what the binaries in
// build/dist really are. This is the backstop for the v0.2.3 mis-publish: stale
// v0.2.2 binaries were repackaged under the 0.2.3 npm version because the only
// guard (a Makefile substring grep) false-matched a "v0.2.3" string the v0.2.2
// binary carried in embedded content. Reading the version from the binary is
// unreliable for the same reason, and executing it triggers first-run init, so
// verify against the archive name instead. Refuse to pack when build/dist holds
// binaries built for a different version than the one being published — this runs
// no matter how build.mjs is invoked (make target or direct `node`).
function verifyReleaseVersion(expected) {
  if (!existsSync(DIST_DIR)) return; // findSourceBinary fails later with a clearer message
  // .zip as well as .tar.gz: the windows archive is a zip (archives.
  // format_overrides in .goreleaser.yaml), and matching only tar.gz would quietly
  // exclude the Windows artifact from this stale-version guard.
  const archiveRe =
    /^vigolium_(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)_(?:linux|darwin|windows)_(?:amd64|arm64)\.(?:tar\.gz|zip)$/;
  const built = new Set();
  for (const f of readdirSync(DIST_DIR)) {
    const m = f.match(archiveRe);
    if (m) built.add(m[1]);
  }
  if (built.size === 0) {
    // Fail closed: build/dist exists (checked above) but holds no goreleaser
    // archives to verify against. Warning-and-continuing here is exactly the
    // fail-open that lets stale unpacked binaries be repackaged under a new
    // version — the v0.2.3 mis-publish this guard exists to stop. If archives
    // are genuinely absent, `make snapshot` must be re-run before packing.
    fail(
      `cannot verify the built version against ${expected}: no goreleaser ` +
        `archives (vigolium_<version>_<os>_<arch>.tar.gz) in ${DIST_DIR}. The ` +
        `unpacked binaries there are unverifiable and may be STALE — packaging ` +
        `them risks shipping a binary that reports the wrong version. Run ` +
        `\`make snapshot\` to rebuild for ${expected} before packing.`,
    );
  }
  if (built.size !== 1 || !built.has(expected)) {
    fail(
      `built-version mismatch: build/dist/ was built for [${[...built].sort().join(", ")}] ` +
        `but this npm publish is version ${expected}. The binaries in build/dist/ are STALE — ` +
        `packaging them would ship a binary whose \`vigolium version\` reports the wrong number ` +
        `(the v0.2.3 mis-publish, where v0.2.2 binaries went out as 0.2.3). ` +
        `Run \`make snapshot\` to rebuild for ${expected} before packing.`,
    );
  }
  info(`verified build/dist/ binaries were built for ${expected}`);
}

// --- locate goreleaser binaries -------------------------------------------

function findSourceBinary(goos, goarch) {
  if (!existsSync(DIST_DIR)) {
    fail(
      `${DIST_DIR} not found. Build cross-platform binaries first ` +
        `(e.g. \`make snapshot\`).`,
    );
  }
  const re = new RegExp(`^vigolium_${goos}_${goarch}(?:_.+)?$`);
  const binName = binaryNameFor(goos);
  const dirs = readdirSync(DIST_DIR)
    .filter((d) => re.test(d))
    .filter((d) => existsSync(path.join(DIST_DIR, d, binName)))
    .sort();
  if (dirs.length === 0) return null;
  if (dirs.length > 1) {
    console.warn(
      `\x1b[33m[warn] multiple goreleaser dirs for ${goos}/${goarch}: ` +
        `${dirs.join(", ")} — using ${dirs[0]}\x1b[0m`,
    );
  }
  return path.join(DIST_DIR, dirs[0], binName);
}

// --- embedded audit blob verification -------------------------------------

// A packaged vigolium binary carries exactly three native executables: itself,
// the per-platform jstangle blob (build-tagged embeds in
// internal/resources/deparos/embed_jstangle_*.go), and the vigolium-audit blob
// staged per target by build/scripts/stage-audit-blob.sh. All three must be
// built for the target platform; a mismatch is the v0.1.15-beta bug, where a
// macOS arm64 audit binary was baked into the linux-x64 package.
//
// This check finds those executables structurally, by locating and validating
// their ELF/Mach-O/PE headers. It deliberately does NOT grep for loader-path
// strings like "/lib64/ld-linux-x86-64.so.2": bun bakes a cross-compile table
// naming every platform's loader into the blobs it builds, so a correct-OS
// blob can and does carry foreign loader strings. That false positive broke
// the 0.4.9 release once bun was new enough to embed the table.
//
// Reading the header fields also makes this an ARCH discriminator, which the
// old string check could not be — a same-OS arch swap is caught here rather
// than being left to the runtime guard in pkg/audit/bin.
const ELF_MACHINE = { 0x3e: "amd64", 0xb7: "arm64" };
const MACHO_CPU = { 0x01000007: "amd64", 0x0100000c: "arm64" };
const PE_MACHINE = { 0x8664: "amd64", 0xaa64: "arm64" };

// findEmbeddedExecutables returns every well-formed native executable header in
// buf, as {os, arch, off}. Each candidate magic is confirmed against further
// header fields so that arbitrary payload bytes matching a 4-byte magic by
// chance are rejected.
function findEmbeddedExecutables(buf) {
  const found = [];

  // ELF64, little-endian, ET_EXEC or ET_DYN.
  const elfMagic = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
  for (let o = buf.indexOf(elfMagic); o !== -1; o = buf.indexOf(elfMagic, o + 1)) {
    if (o + 24 > buf.length) break;
    if (buf[o + 4] !== 2 || buf[o + 5] !== 1 || buf[o + 6] !== 1) continue;
    const eType = buf.readUInt16LE(o + 16);
    if (eType !== 2 && eType !== 3) continue;
    const arch = ELF_MACHINE[buf.readUInt16LE(o + 18)];
    if (!arch) continue;
    if (buf.readUInt32LE(o + 20) !== 1) continue; // EV_CURRENT
    found.push({ os: "linux", arch, off: o });
  }

  // Mach-O 64-bit, little-endian, MH_EXECUTE.
  const machoMagic = Buffer.from([0xcf, 0xfa, 0xed, 0xfe]);
  for (let o = buf.indexOf(machoMagic); o !== -1; o = buf.indexOf(machoMagic, o + 1)) {
    if (o + 32 > buf.length) break;
    const arch = MACHO_CPU[buf.readUInt32LE(o + 4)];
    if (!arch) continue;
    if (buf.readUInt32LE(o + 12) !== 2) continue; // MH_EXECUTE
    const ncmds = buf.readUInt32LE(o + 16);
    if (ncmds === 0 || ncmds > 1024) continue;
    found.push({ os: "darwin", arch, off: o });
  }

  // PE32+ — the COFF header follows the "PE\0\0" signature.
  const peMagic = Buffer.from("PE\0\0", "latin1");
  for (let o = buf.indexOf(peMagic); o !== -1; o = buf.indexOf(peMagic, o + 1)) {
    if (o + 24 > buf.length) break;
    const arch = PE_MACHINE[buf.readUInt16LE(o + 4)];
    if (!arch) continue;
    const sections = buf.readUInt16LE(o + 6);
    if (sections === 0 || sections > 96) continue;
    const optionalHeaderSize = buf.readUInt16LE(o + 20);
    if (optionalHeaderSize !== 240 && optionalHeaderSize !== 224) continue;
    found.push({ os: "win32", arch, off: o });
  }

  return found.sort((a, b) => a.off - b.off);
}

// verifyEmbeddedAudit is the release backstop for the per-target go:embed
// staging: it fails the npm build if a packaged binary embeds a native blob
// built for anything but its own target platform.
function verifyEmbeddedAudit(buf, p) {
  const embedded = findEmbeddedExecutables(buf);
  const foreign = embedded.filter((e) => e.os !== p.os || e.arch !== p.goarch);

  if (foreign.length) {
    const detail = foreign
      .map((e) => `${e.os}/${e.arch} at offset ${e.off}`)
      .join(", ");
    fail(
      `${p.tag}: WRONG-PLATFORM native blob embedded — the ${p.tag} binary ` +
        `carries ${foreign.length} executable(s) built for another platform ` +
        `[${detail}], but every embedded blob must be ${p.os}/${p.goarch}. A ` +
        `foreign vigolium-audit or jstangle blob was baked in at build time ` +
        `(cross-compile packaging bug — check the goreleaser audit staging ` +
        `hook in .goreleaser.yaml and the jstangle embeds in ` +
        `internal/resources/deparos/).`,
    );
  }

  // Zero hits would mean the scan silently stopped matching (a format change),
  // turning this guard into a no-op. The binary itself is always one hit.
  if (embedded.length === 0) {
    fail(
      `${p.tag}: found no native executable headers at all, not even the ` +
        `vigolium binary's own — the embedded-blob scan is not working and ` +
        `cannot be trusted to catch a cross-compile packaging bug.`,
    );
  }

  info(
    `verified ${p.tag} embeds only ${p.os}/${p.goarch} native blobs ` +
      `(${embedded.length} executable headers)`,
  );
}

// verifyEmbeddedJstangle fails the build if a packaged binary embeds a jstangle
// blob built from a different TypeScript tree than the one checked out.
//
// NPM_NEEDS_BUILD only compares the goreleaser archive's VERSION against
// pkg/cli/version.go, so build/dist survives a blob change at the same version:
// rebuilding jstangle and re-running npm-build without `make snapshot` silently
// repackages binaries with the previous blobs still embedded. Version equality
// is not freshness. bun compiles the source fingerprint into the executable as
// a literal string, so it survives into the Go binary that embeds the blob and
// can be checked here.
function verifyEmbeddedJstangle(buf, p) {
  const sourceHash = process.env.VIGOLIUM_JSTANGLE_SOURCE_HASH;
  if (!sourceHash) {
    fail(
      `VIGOLIUM_JSTANGLE_SOURCE_HASH is not set, so the embedded jstangle ` +
        `blob cannot be checked for staleness. Run this via \`make npm-build\` ` +
        `or \`make npm-pack\`, which compute the fingerprint and pass it in.`,
    );
  }
  if (buf.indexOf(Buffer.from(sourceHash, "latin1")) === -1) {
    fail(
      `${p.tag}: STALE jstangle blob embedded — the binary does not carry the ` +
        `current jstangle source fingerprint (${sourceHash}), so it was built ` +
        `before the last jstangle change and would ship an out-of-date ` +
        `analyzer. build/dist is stale even though its version matches: run ` +
        `\`make snapshot\` to rebuild against the current blobs.`,
    );
  }
  info(`verified ${p.tag} embeds the current jstangle build`);
}

// --- staging --------------------------------------------------------------

function writeJson(file, obj) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(obj, null, 2) + "\n");
}

function humanSize(bytes) {
  return `${(bytes / 1048576).toFixed(0)} MB`;
}

async function gzipBuffer(buf, dest) {
  mkdirSync(path.dirname(dest), { recursive: true });
  await pipeline(
    Readable.from([buf]),
    createGzip({ level: 9 }),
    createWriteStream(dest),
  );
}

async function stagePlatformPackage(p) {
  const src = findSourceBinary(p.goos, p.goarch);
  if (!src) {
    if (allowMissing.has(p.tag)) {
      console.warn(
        `\x1b[33m[warn] skipping ${p.tag}: no binary for ${p.goos}/${p.goarch}\x1b[0m`,
      );
      return false;
    }
    fail(
      `Missing binary for ${p.goos}/${p.goarch} (tag ${p.tag}). ` +
        `Run \`make snapshot\` or pass --allow-missing=${p.tag}.`,
    );
  }

  const binBuf = readFileSync(src);
  verifyEmbeddedAudit(binBuf, p);
  verifyEmbeddedJstangle(binBuf, p);

  const pkgDir = path.join(OUT_DIR, `vigolium-${p.tag}`);
  const gzPath = path.join(pkgDir, "vendor", p.tag, "vigolium.gz");

  info(`packaging ${p.tag} (${humanSize(binBuf.length)} -> gzip)`);
  await gzipBuffer(binBuf, gzPath);

  writeJson(path.join(pkgDir, "package.json"), {
    name: NPM_NAME,
    version: platformVersion(p.tag),
    description: `${DESCRIPTION} (${p.tag} prebuilt binary)`,
    license: LICENSE_ID,
    homepage: HOMEPAGE,
    repository: REPOSITORY,
    os: [p.os],
    // npm refuses to install a package whose cpu list excludes the host, so
    // the windows x64 package claims arm64 too — that is the emulation story
    // the rest of the matrix already assumes (there is no bun-windows-arm64
    // target, so an arm64-native build cannot exist). Without this an arm64
    // Windows user's install silently resolves zero platform packages.
    cpu: p.os === "win32" ? [p.cpu, "arm64"] : [p.cpu],
    engines: ENGINES,
    files: ["vendor"],
  });
  if (existsSync(README_SRC)) copyFileSync(README_SRC, path.join(pkgDir, "README.md"));
  if (existsSync(LICENSE_SRC)) copyFileSync(LICENSE_SRC, path.join(pkgDir, "LICENSE"));

  console.log(
    `    -> ${pkgDir}  (vendor unpacked ${humanSize(statSync(gzPath).size)})`,
  );
  return true;
}

function stageMainPackage(stagedTags) {
  const pkgDir = path.join(OUT_DIR, "vigolium");
  const binDir = path.join(pkgDir, "bin");
  mkdirSync(binDir, { recursive: true });
  copyFileSync(LAUNCHER_SRC, path.join(binDir, "vigolium.js"));
  if (existsSync(README_SRC)) copyFileSync(README_SRC, path.join(pkgDir, "README.md"));
  if (existsSync(LICENSE_SRC)) copyFileSync(LICENSE_SRC, path.join(pkgDir, "LICENSE"));

  const optionalDependencies = {};
  for (const p of PLATFORMS) {
    if (!stagedTags.has(p.tag)) continue;
    optionalDependencies[`${NPM_NAME}-${p.tag}`] =
      `npm:${NPM_NAME}@${platformVersion(p.tag)}`;
  }

  writeJson(path.join(pkgDir, "package.json"), {
    name: NPM_NAME,
    version: baseVersion,
    description: DESCRIPTION,
    keywords: KEYWORDS,
    license: LICENSE_ID,
    homepage: HOMEPAGE,
    repository: REPOSITORY,
    type: "module",
    bin: { vigolium: "bin/vigolium.js" },
    engines: ENGINES,
    files: ["bin"],
    optionalDependencies,
  });
  info(`staged main package -> ${pkgDir}`);
}

function npmPack(pkgDir) {
  const res = spawnSync(
    "npm",
    ["pack", "--json", "--pack-destination", OUT_DIR],
    { cwd: pkgDir, encoding: "utf8" },
  );
  if (res.status !== 0) {
    fail(`npm pack failed in ${pkgDir}:\n${res.stderr || res.stdout}`);
  }
  try {
    const out = JSON.parse(res.stdout);
    const name = out[0]?.filename;
    if (name) console.log(`    -> ${path.join(OUT_DIR, name)}`);
  } catch {
    /* non-fatal: tarball is still written */
  }
}

// --- main -----------------------------------------------------------------

info(`vigolium npm build — version ${baseVersion}`);
verifyReleaseVersion(baseVersion);
if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true, force: true });
mkdirSync(OUT_DIR, { recursive: true });

const stagedTags = new Set();
for (const p of PLATFORMS) {
  if (await stagePlatformPackage(p)) stagedTags.add(p.tag);
}
if (stagedTags.size === 0) fail("No platform packages were staged.");
stageMainPackage(stagedTags);

if (doPack) {
  info("running npm pack on each staged package...");
  npmPack(path.join(OUT_DIR, "vigolium"));
  for (const tag of stagedTags) npmPack(path.join(OUT_DIR, `vigolium-${tag}`));
}

info("done.");
console.log(`\nStaged in ${OUT_DIR}:`);
console.log(`  ${NPM_NAME}@${baseVersion}  (main)`);
for (const tag of stagedTags) {
  console.log(`  ${NPM_NAME}@${platformVersion(tag)}  (${tag})`);
}
console.log(
  `\nVerify:  node ${path.join(OUT_DIR, "vigolium", "bin", "vigolium.js")} version`,
);
