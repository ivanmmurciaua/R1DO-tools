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
    build: { outDir: ipfs ? "dist-ipfs" : "dist", emptyOutDir: true },
    plugins: ipfs ? [ipfsHtml()] : [],
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
