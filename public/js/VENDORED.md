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

Not yet catalogued (taken from esm.sh earlier, version only from their header comment): `noble-curves-p256.js`
(@noble/curves 1.3.0), `noble-hashes-sha256.js` and `noble-hashes-utils.js` (@noble/hashes 1.3.3),
`qrcode.js`, `marked.js`. They will be re-sourced from npm and added to the table in the dependency update pass.
