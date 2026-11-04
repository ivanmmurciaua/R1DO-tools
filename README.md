# new-r1do-tools

R1DO suite hub — the single point of identity (create passkey) + the tools, all under **the same origin** (`r1do.com`) as **routes**. **Vite** project, deployable on Vercel.

## Structure
- `index.html` + `src/main.js` → launcher + **create passkey** (discoverable or **device-bound/non-discoverable**, toggle). Processed by Vite.
- `public/js/r1do-auth.js` → the single copy of the auth module (used by the index and the tools).
- `public/notes.html`, `tasks.html`, `chat.html` + `public/js/` → the tools, served as static files as-is (Vite does not touch them). They share `R1DOToolsDB` with the index because of **the same origin** → free SSO, no broker.

## Identity / SSO
- `rpId` = `window.location.hostname`. Served on `r1do.com` → `rpId="r1do.com"` for everything (index + tools) → they share passkeys. (No subdomains, no need for env vars or broker.)
- The credential store is `R1DOToolsDB` (IndexedDB, per-origin).

## Deploy (Vercel)
- Framework: **Vite** (auto). Build: `npm run build`, output: `dist`.
- `cleanUrls` active → `/notes`, `/tasks`, `/chat` (without `.html`).
- No analytics: the pages load no Vercel Web Analytics (or any other tracking) script.

## Crypto v3 (post-quantum hybrid)
Sharing notes and chat messages use a hybrid scheme: it stays secure if EITHER the classical or the
post-quantum half holds. Implemented in `public/js/r1do-auth.js` with `@noble/post-quantum` 0.7.1
(vendored as a deterministic bundle, see `public/js/VENDORED.md` and `tools/vendor-pq.mjs`).
- Identity: the existing P-256 key plus ML-KEM-768 (encryption) and ML-DSA-44 (signatures), all
  derived from the passkey PRF. At-rest keys (notes, tasks, contacts) are unchanged.
- Public card `r1do-id-v3:...`: the three public keys, 2568 bytes binary, ~3.4 KB of text. Users
  exchange it instead of the old 130-hex key, and compare its short SHA-256 fingerprint.
- QR (notes): compact `R1DO-QR-V3:...` form (P-256 + ML-KEM + SHA-256 of the ML-DSA key), 1288
  bytes binary written in base45 (RFC 9285), 1943 characters in one QR alphanumeric segment: QR
  version 26 at error correction L (121 modules) or 30 at M (137 modules). The page uses M when
  each module still gets >= 3 CSS px, else L; tap the QR for a full-screen view.
- Envelope v3: AES-256-GCM key from P-256 ECDH AND ML-KEM-768; signed with ECDSA P-256 AND ML-DSA-44.
  Both signatures cover both sender keys (the P-256 key and the SHA-256 of the ML-DSA key are in
  the signed digest), so neither can be reused next to someone else's key. A sender is "trusted"
  only if both signatures verify and both keys match a contact. ~7 KB per
  message (fine for Waku).
- v2 is retired: v2 envelopes are rejected with "old envelope format (v2): ask the sender to update
  R1DO", and contacts saved with an old key are shown as "old key, re-add" and cannot be used until
  they are added again from a v3 card.
- Tests: `test/r1do-auth.v3.test.mjs` against the frozen `test/vectors-v3.json`.

## Dev
```
npm install
npm run dev      # local
npm run build    # → dist/
npm test         # frozen crypto vectors + vendored file hashes
```
