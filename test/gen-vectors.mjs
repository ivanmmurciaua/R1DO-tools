// Generates test/vectors.json: the frozen, known-good outputs of public/js/r1do-auth.js (v2).
//
// Run ONCE, from the code that is known to work with real user data, and commit the result.
// The vectors are the contract: if a later change (e.g. the post-quantum work) makes the test
// fail, that change would make existing notes / tasks / contacts / messages unreadable.
// Regenerating them to make a red test pass defeats the purpose, so this refuses to overwrite
// an existing file unless --force is passed.
//
//   node test/gen-vectors.mjs           # first time only
//   node test/gen-vectors.mjs --force   # only for a DELIBERATE, versioned format change
import { existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as A from "../public/js/r1do-auth.js";
import { bytesToHex } from "../public/js/noble-hashes-utils.js";

const out = fileURLToPath(new URL("./vectors.json", import.meta.url));
if (existsSync(out) && !process.argv.includes("--force")) {
  console.error("test/vectors.json already exists; refusing to overwrite (see header).");
  process.exit(1);
}

// Fixed, obviously synthetic PRF outputs (never a real user's): A = 0x01..0x20, B = 0xa1..0xc0.
const prfA = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const prfB = Uint8Array.from({ length: 32 }, (_, i) => 0xa1 + i);

const hkdf = {};
for (const [name, label] of Object.entries(A.INFO)) hkdf[name] = bytesToHex(await A.hkdfBits(prfA, label, 32));

const idA = await A.deriveP256Identity(prfA);
const idB = await A.deriveP256Identity(prfB);

// One sealed blob per at-rest key, as notes / tasks / contacts store them.
const plaintexts = {
  NOTES_DEK: "note: r1do vector 1",
  TASKS_DEK: JSON.stringify({ task: "r1do vector 2", done: false }),
  CONTACTS_DEK: JSON.stringify([{ name: "bob", publicKeyHex: idB.publicKeyHex }]),
};
const sealed = {};
for (const [name, text] of Object.entries(plaintexts)) {
  sealed[name] = { plaintext: text, blob: await A.aesEncrypt(await A.hkdfAesKey(prfA, A.INFO[name]), text) };
}

// A message from A to B, as chat and shared notes send it.
const message = "hello bob, from alice (r1do ecies v2 vector)";
const envelope = await A.eciesEncrypt({
  message,
  recipientPublicKeyHex: idB.publicKeyHex,
  senderPrivateKey: idA.privateKey,
  senderPublicKeyHex: idA.publicKeyHex,
});

const vectors = {
  about: "Frozen r1do-auth v2 outputs. Do not regenerate to fix a failing test; see test/gen-vectors.mjs.",
  constants: { DB_NAME: A.DB_NAME, STORE_NAME: A.STORE_NAME, PRF_SALT_SUITE: A.PRF_SALT_SUITE, INFO: A.INFO },
  prfA: bytesToHex(prfA),
  prfB: bytesToHex(prfB),
  hkdf,
  identityA: { privateKey: bytesToHex(idA.privateKey), publicKeyHex: idA.publicKeyHex },
  identityB: { privateKey: bytesToHex(idB.privateKey), publicKeyHex: idB.publicKeyHex },
  sealed,
  ecies: { message, envelope },
};
writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
console.log("wrote test/vectors.json");
