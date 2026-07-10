# new-r1do-tools

R1DO suite hub — the single point of identity (create passkey) + the tools, all under **the same origin** (`r1do.com`) as **routes**. **Vite** project, deployable on Vercel.

## Structure
- `index.html` + `src/main.js` → launcher + **create passkey** (discoverable or **device-bound/non-discoverable**, toggle). Processed by Vite.
- `src/auth/` → `r1do-auth.js` + noble libs (used by the index).
- `public/notes.html`, `tasks.html`, `chat.html` + `public/js/` → the tools, served as static files as-is (Vite does not touch them). They share `R1DOToolsDB` with the index because of **the same origin** → free SSO, no broker.

## Identity / SSO
- `rpId` = `window.location.hostname`. Served on `r1do.com` → `rpId="r1do.com"` for everything (index + tools) → they share passkeys. (No subdomains, no need for env vars or broker.)
- The credential store is `R1DOToolsDB` (IndexedDB, per-origin).

## Deploy (Vercel)
- Framework: **Vite** (auto). Build: `npm run build`, output: `dist`.
- `cleanUrls` active → `/notes`, `/tasks`, `/chat` (without `.html`).
- Web Analytics: the script `/_vercel/insights/script.js` is on all pages; **activate "Web Analytics" in the Vercel dashboard** for it to serve.

## Dev
```
npm install
npm run dev      # local
npm run build    # → dist/
```
