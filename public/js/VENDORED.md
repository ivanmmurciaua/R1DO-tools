# Vendored third-party files

These files are served from this origin instead of a CDN, so the tools (and the IPFS build) do not
run code fetched at load time from a third party. Each file is byte-identical to its upstream source
and its SHA-256 is checked by `npm test` (`test/vendored.test.mjs`): a changed byte fails the test.

To update a file: take it from the npm registry tarball (check its `dist.integrity`), replace the
file, then update the version, source and SHA-256 here and in `test/vendored.test.mjs`.

| File | Package | Version | Source | License | SHA-256 |
|---|---|---|---|---|---|
| `waku-sdk-0.0.31.js` | `@waku/sdk` | 0.0.31 | `bundle/index.js` of the npm tarball (`dist.integrity` `sha512-vlKXitHYMsu8fOXwN+9A7N71Xh3/zVUTO4CEh0zc2ihjtQcazqkU0rX0sOsAJr/XmDZDUAzkQX6aCWULyYRXMw==`), identical to the file previously loaded from unpkg | MIT OR Apache-2.0 | `4f2026f5196af90d5fb414adf02092c3f5173befbf376d46f23f16e0c026f62a` |
| `dompurify-3.4.17.js` | `dompurify` | 3.4.17 | `dist/purify.es.mjs` of the npm tarball (`dist.integrity` `sha512-B/pSlYVHQ58kqISD/yDjuJ1yfzI34m1gF4lAod2bwSRhiN4K5Cl3H8Af7hqB2PmTL911tdEudnnXn5FnhRoz0w==`), used by notes.html to sanitize the rendered markdown preview | MPL-2.0 OR Apache-2.0 | `60c5d5ccbb466de3de3ba863461a92bf134f8c156cef7992da43e0f659bc5cbd` |
| `noble-post-quantum-0.7.1.js` | `@noble/post-quantum` (+ `@noble/hashes`, `@noble/curves`, `@noble/ciphers`) | 0.7.1 (deps 2.4.0, 2.4.0, 2.4.0) | Deterministic bundle, NOT a file copied from a tarball: see below. Used by `r1do-auth.js` (crypto v3) | MIT | `d7dd12ae18febce71fa9d02b040c756f9903777957a7b5167da40c4f9a45eb85` |

## `noble-post-quantum-0.7.1.js` (deterministic bundle)

`@noble/post-quantum` ships as many ESM files that import `@noble/hashes` / `@noble/curves`, and the
static tools are served without a bundler, so this file is a single-file ESM bundle that exports
only `ml_kem768` and `ml_dsa44`. It is produced by `tools/vendor-pq.mjs`, which:

1. `npm pack`s the exact versions below from `https://registry.npmjs.org/` (pinned on every npm
   call, `--ignore-scripts`; it refuses to run if npm config sets another registry for `@noble`),
   and checks each tarball's SHA-512 against the integrity pinned in the script AND the one the
   registry reports (any mismatch aborts);
2. bundles them with the esbuild that vite already installs (0.21.5 at the time of writing), with
   fixed options: ESM, no minification, relative paths only, a fixed banner;
3. writes the file and prints its SHA-256.

| Package | Version | `dist.integrity` | License |
|---|---|---|---|
| `@noble/post-quantum` | 0.7.1 | `sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==` | MIT |
| `@noble/hashes` | 2.4.0 | `sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==` | MIT |
| `@noble/curves` | 2.4.0 | `sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==` | MIT |
| `@noble/ciphers` | 2.4.0 | `sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw==` | MIT |

To reproduce / verify: `node tools/vendor-pq.mjs` (needs network access to the npm registry) must
print `sha256 d7dd12ae18febce71fa9d02b040c756f9903777957a7b5167da40c4f9a45eb85` and leave the file
unchanged (`--out <file>` writes the bundle elsewhere to compare without touching it). The hash depends on the esbuild version too: if a vite update brings a different esbuild,
re-run the script, review the diff of the bundle, and update the hash here and in
`test/vendored.test.mjs`. To move to a newer `@noble/post-quantum`, change the versions and
integrities in the script, rename the output file, and update `r1do-auth.js`, this table and the test.

Not yet catalogued (taken from esm.sh earlier, version only from their header comment): `noble-curves-p256.js`
(@noble/curves 1.3.0), `noble-hashes-sha256.js` and `noble-hashes-utils.js` (@noble/hashes 1.3.3),
`qrcode.js`, `marked.js`. They will be re-sourced from npm and added to the table in the dependency update pass.
