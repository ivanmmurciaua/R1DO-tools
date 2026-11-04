// Integrity of the third-party files served from public/js (see public/js/VENDORED.md).
// A failure means a vendored file changed: either a deliberate update (then update the hash here
// and in VENDORED.md) or something that should not be there.
//
//   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const VENDORED = {
  "waku-sdk-0.0.31.js": "4f2026f5196af90d5fb414adf02092c3f5173befbf376d46f23f16e0c026f62a",
  "dompurify-3.4.17.js": "60c5d5ccbb466de3de3ba863461a92bf134f8c156cef7992da43e0f659bc5cbd",
  // deterministic bundle from tools/vendor-pq.mjs (re-run it: the hash must come out the same)
  "noble-post-quantum-0.7.1.js": "d7dd12ae18febce71fa9d02b040c756f9903777957a7b5167da40c4f9a45eb85",
};

const sha256 = (name) =>
  createHash("sha256").update(readFileSync(new URL(`../public/js/${name}`, import.meta.url))).digest("hex");

for (const [name, want] of Object.entries(VENDORED)) {
  test(`vendored ${name} matches its recorded SHA-256`, () => {
    assert.equal(sha256(name), want);
  });
}

test("no page loads the Waku SDK from a CDN", () => {
  const chat = readFileSync(new URL("../public/chat.html", import.meta.url), "utf8");
  assert.ok(!/unpkg\.com|esm\.sh|jsdelivr/.test(chat), "chat.html still references a CDN");
  assert.ok(chat.includes('"@waku/sdk": "./js/waku-sdk-0.0.31.js"'), "importmap does not point at the vendored file");
});

test("notes.html sanitizes the preview with the vendored DOMPurify", () => {
  const notes = readFileSync(new URL("../public/notes.html", import.meta.url), "utf8");
  assert.ok(notes.includes('import DOMPurify from "./js/dompurify-3.4.17.js";'), "notes.html does not import the vendored DOMPurify");
  assert.ok(!/markdownPreview\.innerHTML\s*=\s*(html|marked)/.test(notes), "the preview is assigned raw marked output");
});

test("r1do-auth.js takes ML-KEM / ML-DSA from the vendored post-quantum bundle", () => {
  const auth = readFileSync(new URL("../public/js/r1do-auth.js", import.meta.url), "utf8");
  assert.ok(auth.includes('from "./noble-post-quantum-0.7.1.js";'), "r1do-auth.js does not import the vendored bundle");
});
