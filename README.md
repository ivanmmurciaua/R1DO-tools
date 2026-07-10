# new-r1do-tools

R1DO suite hub — el punto único de identidad (crear passkey) + las tools, todo
bajo **un mismo origen** (`r1do.com`) como **rutas**. Proyecto **Vite**,
desplegable en Vercel.

## Estructura
- `index.html` + `src/main.js` → launcher + **crear passkey** (discoverable o
  **device-bound/non-discoverable**, toggle). Procesado por Vite.
- `src/auth/` → `r1do-auth.js` + libs noble (usado por el index).
- `public/notes.html`, `tasks.html`, `chat.html` + `public/js/` → las tools,
  servidas como estáticas tal cual (no las toca Vite). Comparten `R1DOToolsDB`
  con el index por ser **el mismo origen** → SSO gratis, sin broker.

## Identidad / SSO
- `rpId` = `window.location.hostname`. Servido en `r1do.com` → `rpId="r1do.com"`
  para TODO (index + tools) → comparten passkeys. (Sin subdominios, no hace falta
  env var ni broker.)
- El store de credenciales es `R1DOToolsDB` (IndexedDB, por-origen).

## Deploy (Vercel)
- Framework: **Vite** (auto). Build: `npm run build`, output: `dist`.
- `cleanUrls` activo → `/notes`, `/tasks`, `/chat` (sin `.html`).
- Web Analytics: el script `/_vercel/insights/script.js` está en todas las
  páginas; **activar "Web Analytics" en el dashboard de Vercel** para que sirva.

## Dev
```
npm install
npm run dev      # local
npm run build    # → dist/
```
