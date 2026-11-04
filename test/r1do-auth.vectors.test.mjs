// Non-regression test for public/js/r1do-auth.js against the frozen vectors in test/vectors.json.
//
// What it protects: every key the tools use is derived from the passkey PRF through HKDF with
// fixed labels and salts. If any byte of that changes, data already stored by users (notes,
// tasks, contacts) and messages already sent can no longer be decrypted. A red test here means
// "this change breaks existing data", never "regenerate the vectors".
//
//   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as A from "../public/js/r1do-auth.js";
import { bytesToHex, hexToBytes } from "../public/js/noble-hashes-utils.js";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const prfA = () => hexToBytes(V.prfA); // fresh copy each time: callers zeroize the PRF
const prfB = () => hexToBytes(V.prfB);

test("constants: PRF salt, HKDF labels and DB names are unchanged", () => {
  assert.equal(A.PRF_SALT_SUITE, V.constants.PRF_SALT_SUITE);
  assert.equal(A.DB_NAME, V.constants.DB_NAME);
  assert.equal(A.STORE_NAME, V.constants.STORE_NAME);
  assert.deepEqual({ ...A.INFO }, V.constants.INFO);
});

test("HKDF: every label derives the same bytes (also pins the HKDF salt)", async () => {
  for (const [name, label] of Object.entries(A.INFO)) {
    assert.equal(bytesToHex(await A.hkdfBits(prfA(), label, 32)), V.hkdf[name], name);
  }
});

test("identity: the P-256 key pair derived from the PRF is unchanged", async () => {
  for (const [prf, want] of [[prfA(), V.identityA], [prfB(), V.identityB]]) {
    const id = await A.deriveP256Identity(prf);
    assert.equal(bytesToHex(id.privateKey), want.privateKey);
    assert.equal(id.publicKeyHex, want.publicKeyHex);
  }
});

test("at rest: notes, tasks and contacts sealed with the old keys still decrypt", async () => {
  for (const [name, { plaintext, blob }] of Object.entries(V.sealed)) {
    const key = await A.hkdfAesKey(prfA(), A.INFO[name]);
    assert.equal(await A.aesDecrypt(key, blob), plaintext, name);
  }
});

test("at rest: each key only opens its own data (labels stay separated)", async () => {
  const tasksKey = await A.hkdfAesKey(prfA(), A.INFO.TASKS_DEK);
  await assert.rejects(A.aesDecrypt(tasksKey, V.sealed.NOTES_DEK.blob));
  const otherUser = await A.hkdfAesKey(prfB(), A.INFO.NOTES_DEK);
  await assert.rejects(A.aesDecrypt(otherUser, V.sealed.NOTES_DEK.blob));
});

// ECIES v2 envelopes: DELIBERATELY RETIRED (versioned format change to crypto v3, see
// test/r1do-auth.v3.test.mjs). Messages are not stored, so nothing at rest depends on v2
// envelopes; the frozen v2 envelope in vectors.json is kept unchanged and must now be REJECTED
// with a clear error instead of being decrypted. Everything above this line stays as it was.
const V2_REJECTED = { message: /old envelope format \(v2\): ask the sender to update R1DO/ };

test("ECIES v2 (retired): the frozen v2 envelope is rejected with a clear error", async () => {
  const myIdentity = await A.deriveIdentityV3(prfB());
  await assert.rejects(A.decryptAnyEnvelope({ envelope: V.ecies.envelope, myIdentity }), V2_REJECTED);
});

test("ECIES v2 (retired): tampered v2 envelopes are rejected the same way, before any crypto", async () => {
  const myIdentity = await A.deriveIdentityV3(prfB());
  const env = V.ecies.envelope;
  const badCt = { ...env, ct: env.ct.map((b, i) => (i === 0 ? b ^ 1 : b)) };
  await assert.rejects(A.decryptAnyEnvelope({ envelope: badCt, myIdentity }), V2_REJECTED);
  await assert.rejects(A.decryptAnyEnvelope({ envelope: { ...env, spk: V.identityB.publicKeyHex }, myIdentity }), V2_REJECTED);
  await assert.rejects(A.decryptAnyEnvelope({ envelope: { ...env, v: "2" }, myIdentity }), V2_REJECTED);
});

test("ECIES v2 (retired): v2 envelopes can no longer be produced", () => {
  assert.equal(A.eciesEncrypt, undefined);
  assert.equal(A.eciesDecrypt, undefined);
});
