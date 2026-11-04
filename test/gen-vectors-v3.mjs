// Generates test/vectors-v3.json: the frozen, known-good outputs of the crypto v3 additions in
// public/js/r1do-auth.js (post-quantum identity, public card, QR payload, hybrid envelope).
//
// Same contract as test/gen-vectors.mjs: run ONCE and commit the result. A later change that turns
// test/r1do-auth.v3.test.mjs red would change people's v3 identity (cards already handed out) or
// make v3 envelopes unreadable, so this refuses to overwrite an existing file unless --force is
// passed, which is only for a DELIBERATE, versioned format change.
//
//   node test/gen-vectors-v3.mjs           # first time only
//   node test/gen-vectors-v3.mjs --force   # only for a DELIBERATE, versioned format change
import { existsSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as A from "../public/js/r1do-auth.js";
import { sha256 } from "../public/js/noble-hashes-sha256.js";
import { bytesToHex } from "../public/js/noble-hashes-utils.js";

const out = fileURLToPath(new URL("./vectors-v3.json", import.meta.url));
if (existsSync(out) && !process.argv.includes("--force")) {
  console.error("test/vectors-v3.json already exists; refusing to overwrite (see header).");
  process.exit(1);
}

// The same synthetic PRF outputs as vectors.json: A = 0x01..0x20, B = 0xa1..0xc0.
const prfA = () => Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const prfB = () => Uint8Array.from({ length: 32 }, (_, i) => 0xa1 + i);
const h = (u8) => bytesToHex(sha256(u8));

const identity = async (prf) => {
  const id = await A.deriveIdentityV3(prf());
  return {
    publicKeyHex: id.publicKeyHex,
    mlkemPublicKeySha256: h(id.mlkemPublicKey),
    mlkemSecretKeySha256: h(id.mlkemSecretKey),
    mldsaPublicKeySha256: h(id.mldsaPublicKey),
    mldsaSecretKeySha256: h(id.mldsaSecretKey),
    card: A.encodeCard(id),
    cardFingerprint: A.cardFingerprint(A.encodeCardBytes(id)),
    qrText: A.encodeQrText(id),
  };
};

const idA = await A.deriveIdentityV3(prfA());
const idB = await A.deriveIdentityV3(prfB());

// A message from A to B, as chat and shared notes send it (B as a contact added from the QR).
const message = "hello bob, from alice (r1do ecies v3 vector)";
const envelope = await A.eciesEncryptV3({
  message,
  recipient: A.parsePublicIdentity(A.encodeQrText(idB)),
  sender: idA,
});

const vectors = {
  about: "Frozen r1do-auth v3 outputs. Do not regenerate to fix a failing test; see test/gen-vectors-v3.mjs.",
  constants: {
    INFO_V3: A.INFO_V3,
    CARD_PREFIX: A.CARD_PREFIX,
    QR_PREFIX: A.QR_PREFIX,
    CARD_BYTES: A.CARD_BYTES,
    QR_BYTES: A.QR_BYTES,
  },
  prfA: bytesToHex(prfA()),
  prfB: bytesToHex(prfB()),
  identityA: await identity(prfA),
  identityB: await identity(prfB),
  ecies: { message, envelope },
};
writeFileSync(out, JSON.stringify(vectors, null, 2) + "\n");
console.log("wrote test/vectors-v3.json");
