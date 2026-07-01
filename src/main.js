// R1DO id — entry point. The index is the single place where the passkey is
// created (the seed of the identity broker). Everything else (notes/tasks/chat/
// wallet) will pull from this identity.
import { registerPasskey, listCredentials } from "./auth/r1do-auth.js";

const byId = (id) => document.getElementById(id);
const statusEl = byId("status");
const btn = byId("create-passkey");
const input = byId("username");
const identityEl = document.querySelector(".identity");

function setStatus(msg, kind = "") {
  statusEl.textContent = msg;
  statusEl.className = "status" + (kind ? " " + kind : "");
}

// Show the "create passkey" block ONLY when R1DOToolsDB is empty. Once there's
// any credential, the index is just a launcher — each tool handles its own
// login/register against the same store. On read error, show it (fail-safe so a
// new user can always create one).
(async () => {
  try {
    const creds = await listCredentials();
    if (!creds || creds.length === 0) identityEl.style.display = "block";
  } catch (e) {
    console.warn("[id] could not read cred store — showing identity:", e);
    identityEl.style.display = "block";
  }
})();

btn.addEventListener("click", async () => {
  const username = input.value.trim();
  if (!username) {
    setStatus("Enter a username first.", "err");
    return;
  }
  const deviceBound = byId("device-bound").checked;
  btn.disabled = true;
  setStatus("Creating your passkey…");
  try {
    const res = await registerPasskey(username, { deviceBound });
    console.log(`[id] registerPasskey ✓ (${deviceBound ? "device-bound/non-discoverable" : "discoverable"})`, res);
    setStatus(`Passkey created for "${username}" (${deviceBound ? "device-bound" : "discoverable"}).`, "ok");
  } catch (e) {
    console.error("[id] registerPasskey failed:", e);
    setStatus(e?.message || "Could not create the passkey.", "err");
  } finally {
    btn.disabled = false;
  }
});
