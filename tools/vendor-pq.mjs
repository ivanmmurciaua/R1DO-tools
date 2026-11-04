// Reproducible vendoring of @noble/post-quantum for the static tools (see public/js/VENDORED.md).
//
// @noble/post-quantum is multi-file ESM with its own @noble deps, and the tools in public/ are
// served as-is (no bundler), so this produces ONE self-contained ESM file that exports only
// ml_kem768 and ml_dsa44:
//
//   0. refuse to run if npm config would send a packed scope to another registry (a scoped
//      `@scope:registry` wins over --registry), then pin the public registry on every npm call
//      and pack with --ignore-scripts (no lifecycle scripts of the fetched packages run);
//   1. `npm pack` the pinned versions into a temp dir and check every tarball against the
//      integrity pinned below AND the one the registry reports (a mismatch aborts), and its
//      tarball URL against the pinned registry;
//   2. unpack them into a throwaway node_modules;
//   3. bundle with the esbuild that vite already installs (no minify, fixed options, relative
//      paths only), so the same inputs give the same bytes;
//   4. write public/js/noble-post-quantum-0.7.1.js and print its SHA-256.
//
// Run it twice: the hash must not change. Then record the hash in VENDORED.md and in
// test/vendored.test.mjs. --out writes somewhere else (e.g. to compare against the committed
// bundle without overwriting it).
//
//   node tools/vendor-pq.mjs
//   node tools/vendor-pq.mjs --out /tmp/check.js
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Exact versions (the ones @noble/post-quantum 0.7.1 depends on) and their npm dist.integrity.
const PACKAGES = [
  ["@noble/post-quantum", "0.7.1", "sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q=="],
  ["@noble/hashes", "2.4.0", "sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA=="],
  ["@noble/curves", "2.4.0", "sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew=="],
  ["@noble/ciphers", "2.4.0", "sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw=="],
];

const REGISTRY = "https://registry.npmjs.org/";

const outArg = process.argv.indexOf("--out");
if (outArg !== -1 && !process.argv[outArg + 1]) throw new Error("--out needs a file path");
const OUT =
  outArg !== -1
    ? resolve(process.argv[outArg + 1])
    : fileURLToPath(new URL("../public/js/noble-post-quantum-0.7.1.js", import.meta.url));

// The esbuild that vite resolves (no extra devDependency).
const requireFromVite = createRequire(createRequire(import.meta.url).resolve("vite/package.json"));
const esbuild = requireFromVite("esbuild");

const npm = (...args) => execFileSync("npm", args, { encoding: "utf8" }).trim();
const sameRegistry = (url) => url.replace(/\/*$/, "/") === REGISTRY;

// A scoped registry (e.g. "@noble:registry" in any .npmrc or env) overrides --registry for that
// scope, so check what npm would really use for every scope packed below.
for (const scope of new Set(PACKAGES.map(([name]) => name.split("/")[0]))) {
  const scoped = npm("config", "get", `${scope}:registry`);
  if (scoped !== "undefined" && scoped !== "" && !sameRegistry(scoped))
    throw new Error(`npm config sets ${scope}:registry=${scoped}; refusing (expected ${REGISTRY})`);
}

const work = mkdtempSync(join(tmpdir(), "r1do-vendor-pq-"));
try {
  const tarballs = join(work, "tarballs");
  mkdirSync(tarballs);

  for (const [name, version, pinned] of PACKAGES) {
    const spec = `${name}@${version}`;
    const dist = JSON.parse(
      npm("view", spec, "dist.integrity", "dist.tarball", "--json", `--registry=${REGISTRY}`),
    );
    const registry = dist["dist.integrity"];
    if (registry !== pinned) throw new Error(`${spec}: registry integrity ${registry} != pinned ${pinned}`);
    if (!String(dist["dist.tarball"]).startsWith(REGISTRY))
      throw new Error(`${spec}: tarball ${dist["dist.tarball"]} is not on ${REGISTRY}`);

    const [packed] = JSON.parse(
      npm(
        "pack",
        spec,
        "--pack-destination",
        tarballs,
        "--json",
        "--ignore-scripts",
        `--registry=${REGISTRY}`,
      ),
    );
    const file = join(tarballs, packed.filename);
    const actual = "sha512-" + createHash("sha512").update(readFileSync(file)).digest("base64");
    if (actual !== pinned) throw new Error(`${spec}: tarball integrity ${actual} != pinned ${pinned}`);

    const dest = join(work, "node_modules", ...name.split("/"));
    mkdirSync(dest, { recursive: true });
    execFileSync("tar", ["-xzf", file, "-C", dest, "--strip-components=1"]);
    console.log(`ok  ${spec}  ${actual}`);
  }

  writeFileSync(
    join(work, "entry.js"),
    'export { ml_kem768 } from "@noble/post-quantum/ml-kem.js";\n' +
      'export { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";\n',
  );

  const banner =
    "/* @noble/post-quantum 0.7.1 (ml_kem768, ml_dsa44 only), with @noble/hashes 2.4.0,\n" +
    "   @noble/curves 2.4.0, @noble/ciphers 2.4.0. MIT License, (c) Paul Miller (paulmillr.com).\n" +
    `   Deterministic bundle produced by tools/vendor-pq.mjs (esbuild ${esbuild.version}); do not edit. */`;

  const result = await esbuild.build({
    absWorkingDir: work,
    entryPoints: ["entry.js"],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    minify: false,
    treeShaking: true,
    legalComments: "inline",
    charset: "utf8",
    banner: { js: banner },
    write: false,
    logLevel: "warning",
  });
  const code = result.outputFiles[0].contents;
  writeFileSync(OUT, code);

  const sha = createHash("sha256").update(code).digest("hex");
  console.log(`wrote ${OUT}  ${code.length} bytes  sha256 ${sha}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
