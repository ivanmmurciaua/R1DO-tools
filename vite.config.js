import { defineConfig } from "vite";

// Two builds from the same sources:
//   npm run build       -> dist/       (Vercel: root base, clean URLs like /notes)
//   npm run build:ipfs  -> dist-ipfs/  (IPFS: no Wallet card, relative paths so it works under
//                                       /ipfs/<cid>/, links to the .html files since IPFS
//                                       gateways have no clean URLs)
export default defineConfig(({ mode }) => {
  const ipfs = mode === "ipfs";
  return {
    base: ipfs ? "./" : "/",
    // es2022 (top-level await in src/main.js): WebAuthn PRF already requires Chrome 132+,
    // Safari 17.4+ or Firefox 130+, so no supported browser is lost.
    build: { outDir: ipfs ? "dist-ipfs" : "dist", emptyOutDir: true, target: "es2022" },
    plugins: ipfs ? [ipfsHtml()] : [],
    // Test from a phone through an ngrok HTTPS tunnel (WebAuthn needs HTTPS + a real hostname).
    // A leading dot matches every subdomain, i.e. https://*.ngrok-free.app.
    server: { allowedHosts: [".ngrok-free.app"] },
    preview: { allowedHosts: [".ngrok-free.app"] },
  };
});

// IPFS-only HTML pass over index.html: drop the Wallet card and point the tool links at the
// static .html pages.
function ipfsHtml() {
  return {
    name: "r1do-ipfs-html",
    transformIndexHtml(html) {
      const out = html
        .replace(/[ \t]*<!-- wallet:start[\s\S]*?<!-- wallet:end -->\n?/, "")
        .replace(/href="\/(notes|tasks|chat)"/g, 'href="$1.html"');
      if (out.includes("wallet.r1do.com")) throw new Error("IPFS build: the Wallet card was not stripped");
      return out;
    },
  };
}
