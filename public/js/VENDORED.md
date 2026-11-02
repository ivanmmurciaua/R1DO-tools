# Vendored third-party files

These files are served from this origin instead of a CDN, so the tools (and the IPFS build) do not
run code fetched at load time from a third party. Each file is byte-identical to its upstream source
and its SHA-256 is checked by `npm test` (`test/vendored.test.mjs`): a changed byte fails the test.

To update a file: take it from the npm registry tarball (check its `dist.integrity`), replace the
file, then update the version, source and SHA-256 here and in `test/vendored.test.mjs`.

| File | Package | Version | Source | License | SHA-256 |
|---|---|---|---|---|---|
| `waku-sdk-0.0.31.js` | `@waku/sdk` | 0.0.31 | `bundle/index.js` of the npm tarball (`dist.integrity` `sha512-vlKXitHYMsu8fOXwN+9A7N71Xh3/zVUTO4CEh0zc2ihjtQcazqkU0rX0sOsAJr/XmDZDUAzkQX6aCWULyYRXMw==`), identical to the file previously loaded from unpkg | MIT OR Apache-2.0 | `4f2026f5196af90d5fb414adf02092c3f5173befbf376d46f23f16e0c026f62a` |

Not yet catalogued (taken from esm.sh earlier, version only from their header comment): `noble-curves-p256.js`
(@noble/curves 1.3.0), `noble-hashes-sha256.js` and `noble-hashes-utils.js` (@noble/hashes 1.3.3),
`qrcode.js`, `marked.js`. They will be re-sourced from npm and added to the table in the dependency update pass.
