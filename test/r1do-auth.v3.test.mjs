// Crypto v3 (post-quantum hybrid) tests for public/js/r1do-auth.js against the frozen vectors in
// test/vectors-v3.json, plus round trips, strict parsing and tamper cases.
//
// What it protects: the v3 identity (ML-KEM-768 + ML-DSA-44 next to the v2 P-256 key) is derived
// from the passkey PRF, and the public card built from it is what people hand to each other. If a
// byte of the derivation, the card layout or the envelope changes, cards already exchanged stop
// matching and v3 messages stop opening. A red test means "this change breaks existing v3 users",
// never "regenerate the vectors".
//
//   npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as A from "../public/js/r1do-auth.js";
import { sha256 } from "../public/js/noble-hashes-sha256.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "../public/js/noble-hashes-utils.js";
import { p256 } from "../public/js/noble-curves-p256.js";
import { ml_dsa44 } from "../public/js/noble-post-quantum-0.7.1.js";
import QRCode from "../public/js/qrcode.js";

const V3 = JSON.parse(readFileSync(new URL("./vectors-v3.json", import.meta.url), "utf8"));
const V2 = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));
const prfA = () => hexToBytes(V3.prfA); // fresh copy each time: callers zeroize the PRF
const prfB = () => hexToBytes(V3.prfB);
const prfC = () => Uint8Array.from({ length: 32 }, (_, i) => 0x51 + i); // a third party
const h = (u8) => bytesToHex(sha256(u8));

// Flip one bit of a base64url / hex envelope field.
const flipB64 = (s, i = 0) => {
  const b = A.b64urlDecode(s);
  b[i] ^= 1;
  return A.b64urlEncode(b);
};
const flipHex = (s, i = 0) => {
  const b = hexToBytes(s);
  b[i] ^= 1;
  return bytesToHex(b);
};

test("v3 constants: labels, prefixes and sizes are unchanged", () => {
  assert.deepEqual({ ...A.INFO_V3 }, V3.constants.INFO_V3);
  assert.equal(A.CARD_PREFIX, V3.constants.CARD_PREFIX);
  assert.equal(A.QR_PREFIX, V3.constants.QR_PREFIX);
  assert.equal(A.CARD_BYTES, V3.constants.CARD_BYTES);
  assert.equal(A.QR_BYTES, V3.constants.QR_BYTES);
  // v2 labels stay where they were (INFO is pinned by the v2 vectors).
  assert.equal(A.INFO.ID_MLKEM, undefined);
  assert.equal(A.INFO.ID_MLDSA, undefined);
});

test("v3 identity: PQ keys, card and QR derived from the PRF are unchanged", async () => {
  for (const [prf, want, v2] of [[prfA, V3.identityA, V2.identityA], [prfB, V3.identityB, V2.identityB]]) {
    const id = await A.deriveIdentityV3(prf());
    assert.equal(id.publicKeyHex, v2.publicKeyHex, "P-256 part is the frozen v2 identity");
    assert.equal(id.publicKeyHex, want.publicKeyHex);
    assert.equal(h(id.mlkemPublicKey), want.mlkemPublicKeySha256);
    assert.equal(h(id.mlkemSecretKey), want.mlkemSecretKeySha256);
    assert.equal(h(id.mldsaPublicKey), want.mldsaPublicKeySha256);
    assert.equal(h(id.mldsaSecretKey), want.mldsaSecretKeySha256);
    assert.equal(A.encodeCard(id), want.card);
    assert.equal(A.cardFingerprint(A.encodeCardBytes(id)), want.cardFingerprint);
    assert.equal(A.cardFingerprint(want.card), want.cardFingerprint);
    assert.equal(A.encodeQrText(id), want.qrText);
  }
});

test("v3 identity: derivePqIdentity is independent from the P-256 key and per user", async () => {
  const a = await A.derivePqIdentity(prfA());
  const b = await A.derivePqIdentity(prfB());
  assert.notEqual(h(a.mlkemPublicKey), h(b.mlkemPublicKey));
  assert.notEqual(h(a.mldsaPublicKey), h(b.mldsaPublicKey));
  assert.equal(a.mlkemPublicKey.length, 1184);
  assert.equal(a.mldsaPublicKey.length, 1312);
});

test("card + QR: encode/decode round trips and sizes", async () => {
  const id = await A.deriveIdentityV3(prfA());
  const card = A.encodeCard(id);
  assert.equal(A.encodeCardBytes(id).length, 2568);
  assert.equal(A.encodeQrPayload(id).length, 1288);

  const c = A.decodeCard(card);
  assert.equal(bytesToHex(c.p256), id.publicKeyHex);
  assert.equal(h(c.mlkem), h(id.mlkemPublicKey));
  assert.equal(h(c.mldsaPk), h(id.mldsaPublicKey));
  assert.equal(bytesToHex(c.mldsaHash), h(id.mldsaPublicKey));
  assert.deepEqual(A.decodeCard(A.encodeCardBytes(id)), c, "binary and text decode agree");

  const q = A.decodeQrPayload(A.encodeQrPayload(id));
  assert.deepEqual(A.decodeQrPayload(A.encodeQrText(id)), q, "binary and text decode agree");
  assert.equal(bytesToHex(q.mldsaHash), h(id.mldsaPublicKey));

  const fromCard = A.parsePublicIdentity(card);
  const fromQr = A.parsePublicIdentity(A.encodeQrText(id));
  assert.equal(fromCard.p256, fromQr.p256);
  assert.equal(fromCard.mlkem, fromQr.mlkem);
  assert.equal(fromCard.mldsaHash, fromQr.mldsaHash);
  assert.equal(typeof fromCard.mldsaPk, "string");
  assert.equal(fromQr.mldsaPk, undefined);
  assert.ok(A.isV3Contact({ name: "a", ...fromCard }));
  assert.ok(A.isV3Contact({ name: "a", ...fromQr }));
  // whitespace / line breaks from copy-paste are tolerated
  assert.deepEqual(A.parsePublicIdentity(` ${card.slice(0, 50)}\n${card.slice(50)} `), fromCard);
});

test("card + QR: wrong prefix, length, magic, encoding and keys are rejected", async () => {
  const id = await A.deriveIdentityV3(prfA());
  const bytes = A.encodeCardBytes(id);
  const asCard = (b) => A.CARD_PREFIX + A.b64urlEncode(b);

  assert.throws(() => A.decodeCard("r1do-id-v2:" + A.b64urlEncode(bytes)), /Not an R1DO v3 card/);
  assert.throws(() => A.decodeCard(asCard(bytes.slice(0, -1))), /expected 2568 bytes/);
  assert.throws(() => A.decodeCard(asCard(new Uint8Array([...bytes, 0]))), /expected 2568 bytes/);
  const badMagic = bytes.slice();
  badMagic[6] ^= 1;
  assert.throws(() => A.decodeCard(asCard(badMagic)), /bad magic/);
  const badPoint = bytes.slice();
  badPoint[7 + 64] ^= 1; // last byte of the P-256 y coordinate
  assert.throws(() => A.decodeCard(asCard(badPoint)));
  const compressed = bytes.slice();
  compressed[7] = 0x02;
  assert.throws(() => A.decodeCard(asCard(compressed)), /P-256/);
  const badEk = bytes.slice();
  badEk[7 + 65] = 0xff; // first ML-KEM coefficient becomes >= q
  badEk[7 + 65 + 1] = 0xff;
  assert.throws(() => A.decodeCard(asCard(badEk)));
  assert.throws(() => A.decodeCard(A.encodeCard(id).slice(0, -1) + "!"), /base64url/);
  // non-canonical: last char with non-zero padding bits
  const t = A.encodeCard(id);
  const last = t.at(-1);
  const alt = String.fromCharCode(last.charCodeAt(0) + 1);
  assert.throws(() => A.decodeCard(t.slice(0, -1) + alt));

  const qr = A.encodeQrPayload(id);
  assert.throws(() => A.decodeQrPayload(qr.slice(0, -1)), /expected 1288 bytes/);
  const qrMagic = qr.slice();
  qrMagic[0] ^= 1;
  assert.throws(() => A.decodeQrPayload(qrMagic), /bad magic/);
  assert.throws(() => A.decodeQrPayload(bytes), /expected 1288 bytes/, "a card is not a QR payload");
  assert.throws(() => A.decodeCard(qr), /expected 2568 bytes/, "a QR payload is not a card");

  assert.throws(() => A.parsePublicIdentity(V2.identityA.publicKeyHex), /old \(v2\) public key/);
  assert.throws(() => A.parsePublicIdentity("hello"), /Expected an R1DO v3 card/);

  // a stored contact whose full ML-DSA key does not match its hash is not a valid v3 contact
  const c = A.parsePublicIdentity(A.encodeCard(id));
  assert.equal(A.isV3Contact({ ...c, mldsaHash: "00".repeat(32) }), false);
  assert.equal(A.isV3Contact({ name: "old", publicKey: V2.identityA.publicKeyHex }), false);
});

test("ECIES v3: the frozen envelope decrypts and both signatures verify", async () => {
  const b = await A.deriveIdentityV3(prfB());
  const r = await A.decryptAnyEnvelope({ envelope: V3.ecies.envelope, myIdentity: b });
  assert.equal(r.text, V3.ecies.message);
  assert.equal(r.verified, true);
  assert.equal(r.senderPublicKeyHex, V3.identityA.publicKeyHex);
  assert.equal(r.senderMldsaHash, V3.identityA.mldsaPublicKeySha256);
  assert.equal(r.senderMldsaPk, V3.ecies.envelope.spq);

  const alice = { name: "alice", ...A.parsePublicIdentity(V3.identityA.card) };
  const aliceQr = { name: "alice", ...A.parsePublicIdentity(V3.identityA.qrText) };
  assert.equal(A.matchSender(r, [alice]).trust, "trusted");
  assert.equal(A.matchSender(r, [aliceQr]).contact, aliceQr);
  assert.equal(A.matchSender(r, []).trust, "unknown");
  // a legacy contact with the same P-256 key is never trusted for v3
  assert.equal(A.matchSender(r, [{ name: "old", publicKey: V3.identityA.publicKeyHex }]).trust, "unknown");
});

test("ECIES v3: a fresh round trip works (recipient from card and from QR)", async () => {
  const a = await A.deriveIdentityV3(prfA());
  const b = await A.deriveIdentityV3(prfB());
  for (const recipient of [A.parsePublicIdentity(A.encodeCard(b)), A.parsePublicIdentity(A.encodeQrText(b))]) {
    const env = await A.eciesEncryptV3({ message: "round trip ✓ ñ", recipient, sender: a });
    assert.equal(env.v, 3);
    const r = await A.decryptAnyEnvelope({ envelope: env, myIdentity: b });
    assert.equal(r.text, "round trip ✓ ñ");
    assert.equal(r.verified, true);
  }
});

test("ECIES v3: tampering, swapped senders and the wrong recipient are detected", async () => {
  const a = await A.deriveIdentityV3(prfA());
  const b = await A.deriveIdentityV3(prfB());
  const env = V3.ecies.envelope;
  const open = (envelope, myIdentity = b) => A.decryptAnyEnvelope({ envelope, myIdentity });
  const alice = { name: "alice", ...A.parsePublicIdentity(V3.identityA.card) };

  // Confidentiality / integrity: any change to the encryption transcript fails AES-GCM.
  await assert.rejects(open({ ...env, kem: flipB64(env.kem) }), undefined, "kem ct tamper");
  await assert.rejects(open({ ...env, ct: flipB64(env.ct) }), undefined, "ct tamper");
  await assert.rejects(open({ ...env, iv: flipB64(env.iv) }), undefined, "iv tamper");
  await assert.rejects(open({ ...env, epk: flipHex(env.epk, 64) }), undefined, "epk tamper");
  await assert.rejects(open(env, a), undefined, "wrong recipient");

  // Authenticity: each signature counts on its own.
  assert.equal((await open({ ...env, sig: flipHex(env.sig, 5) })).verified, false, "ECDSA sig tamper");
  assert.equal((await open({ ...env, pqsig: flipB64(env.pqsig, 5) })).verified, false, "ML-DSA sig tamper");
  assert.equal((await open({ ...env, spq: A.b64urlEncode(b.mldsaPublicKey) })).verified, false, "swapped spq");
  assert.equal((await open({ ...env, spk: b.publicKeyHex })).verified, false, "swapped spk");
  assert.equal((await open({ ...env, sig: "00".repeat(64) })).verified, false, "zero ECDSA sig");

  // A third party re-signing with ITS OWN keys verifies, but is not alice.
  const c = await A.deriveIdentityV3(prfC());
  const forged = await A.eciesEncryptV3({ message: "hi, it's alice", recipient: A.parsePublicIdentity(A.encodeCard(b)), sender: c });
  const rf = await open(forged);
  assert.equal(rf.verified, true);
  assert.equal(A.matchSender(rf, [alice]).trust, "unknown");
  // ...and claiming alice's keys without her secrets does not verify.
  const claimed = await open({ ...forged, spk: alice.p256, spq: alice.mldsaPk });
  assert.equal(claimed.verified, false);
  assert.equal(A.matchSender(claimed, [alice]).trust, "invalid");
  // Mixed: alice's real ECDSA identity with an attacker ML-DSA key is not alice either.
  const mixed = await A.eciesEncryptV3({
    message: "mixed",
    recipient: A.parsePublicIdentity(A.encodeCard(b)),
    sender: { ...a, mldsaSecretKey: c.mldsaSecretKey, mldsaPublicKey: c.mldsaPublicKey },
  });
  const rm = await open(mixed);
  assert.equal(rm.verified, true);
  assert.equal(A.matchSender(rm, [alice]).trust, "unknown");

  // Malformed fields are refused before any crypto.
  await assert.rejects(open({ ...env, kem: env.kem.slice(0, -4) }), /envelope kem/);
  await assert.rejects(open({ ...env, spq: env.spq.slice(0, -4) }), /envelope spq/);
  await assert.rejects(open({ ...env, epk: env.epk.slice(2) }), /envelope epk/);
});

test("ECIES v3: the signed digest is the documented one and binds both sender keys", async () => {
  const b = await A.deriveIdentityV3(prfB());
  const env = V3.ecies.envelope;
  const binding = sha256(new Uint8Array([...b.publicKey, ...b.mlkemPublicKey]));
  const fields = [hexToBytes(env.epk), A.b64urlDecode(env.kem), A.b64urlDecode(env.iv), A.b64urlDecode(env.ct)];
  const spk = hexToBytes(env.spk);
  const spq = A.b64urlDecode(env.spq);
  // Independent recomputation of the layout documented in r1do-auth.js:
  // tag || spk || sha256(spq) || epk || kemCt || iv || ct || recipient binding.
  const documented = sha256(
    new Uint8Array([...utf8ToBytes("r1do/ecies-sig/v3"), ...spk, ...sha256(spq), ...fields.flat().flatMap((f) => [...f]), ...binding]),
  );
  assert.equal(bytesToHex(A.sigDigestV3(spk, spq, ...fields, binding)), bytesToHex(documented));
  assert.ok(p256.verify(hexToBytes(env.sig), documented, spk));
  assert.ok(ml_dsa44.verify(A.b64urlDecode(env.pqsig), documented, spq));
});

test("ECIES v3: a relay cannot keep one sender signature and swap in its own key for the other", async () => {
  const a = await A.deriveIdentityV3(prfA());
  const b = await A.deriveIdentityV3(prfB());
  const c = await A.deriveIdentityV3(prfC()); // the relay
  // A fresh envelope (not the frozen one), so the test exercises whatever digest the code signs.
  const message = "from alice, via a relay";
  const env = await A.eciesEncryptV3({ message, recipient: A.parsePublicIdentity(A.encodeCard(b)), sender: a });
  const alice = { name: "alice", ...A.parsePublicIdentity(V3.identityA.card) };
  const open = (envelope) => A.decryptAnyEnvelope({ envelope, myIdentity: b });
  const binding = sha256(new Uint8Array([...b.publicKey, ...b.mlkemPublicKey]));
  const fields = [hexToBytes(env.epk), A.b64urlDecode(env.kem), A.b64urlDecode(env.iv), A.b64urlDecode(env.ct)];
  // The strongest relay signs exactly what the verifier will hash for the forged envelope.
  const digestFor = (spk, spq) => A.sigDigestV3(spk, spq, ...fields, binding);

  // Keep alice's ECDSA signature, replace spq + pqsig with the relay's own valid ML-DSA signature.
  const pqSwap = {
    ...env,
    spq: A.b64urlEncode(c.mldsaPublicKey),
    pqsig: A.b64urlEncode(ml_dsa44.sign(digestFor(hexToBytes(env.spk), c.mldsaPublicKey), c.mldsaSecretKey)),
  };
  assert.equal(A.matchSender(await open(env), [alice]).trust, "trusted", "the untouched envelope is alice's");
  const r1 = await open(pqSwap);
  assert.equal(r1.text, message, "the ciphertext itself is untouched");
  assert.equal(r1.verified, false, "alice's ECDSA signature does not cover the relay's ML-DSA key");
  assert.equal(A.matchSender(r1, [alice]).trust, "invalid");
  // Same, with the relay's ML-DSA signature over the digest computed with alice's spq.
  const pqSwap2 = {
    ...pqSwap,
    pqsig: A.b64urlEncode(ml_dsa44.sign(digestFor(hexToBytes(env.spk), A.b64urlDecode(env.spq)), c.mldsaSecretKey)),
  };
  assert.equal((await open(pqSwap2)).verified, false);

  // Mirror: keep alice's ML-DSA signature, replace spk + sig with the relay's own valid ECDSA signature.
  const ecSwap = {
    ...env,
    spk: c.publicKeyHex,
    sig: bytesToHex(p256.sign(digestFor(c.publicKey, A.b64urlDecode(env.spq)), c.privateKey).toCompactRawBytes()),
  };
  const r2 = await open(ecSwap);
  assert.equal(r2.verified, false, "alice's ML-DSA signature does not cover the relay's P-256 key");
  assert.equal(A.matchSender(r2, [alice]).trust, "invalid");

  // A malformed spk is refused before any crypto (like spq).
  await assert.rejects(open({ ...env, spk: "zz" }), /envelope spk/);
});

test("contacts: validateV3Contact runs the full key checks a card or QR gets", async () => {
  const id = await A.deriveIdentityV3(prfA());
  const fromCard = A.parsePublicIdentity(A.encodeCard(id));
  const fromQr = A.parsePublicIdentity(A.encodeQrText(id));
  assert.deepEqual(A.validateV3Contact({ name: "a", ...fromCard }), fromCard);
  assert.deepEqual(A.validateV3Contact({ name: "a", ...fromQr }), fromQr);
  // normalizes hex case
  assert.deepEqual(
    A.validateV3Contact({ ...fromCard, p256: fromCard.p256.toUpperCase(), mldsaHash: fromCard.mldsaHash.toUpperCase() }),
    fromCard,
  );

  // Well-formed (isV3Contact passes) but not a point on P-256.
  const offCurve = { ...fromCard, p256: flipHex(fromCard.p256, 64) };
  assert.equal(A.isV3Contact(offCurve), true);
  assert.throws(() => A.validateV3Contact(offCurve));
  // Well-formed but an ML-KEM key that fails the FIPS 203 modulus check.
  const ek = A.b64urlDecode(fromCard.mlkem);
  ek[0] = 0xff;
  ek[1] = 0xff;
  const badEk = { ...fromCard, mlkem: A.b64urlEncode(ek) };
  assert.equal(A.isV3Contact(badEk), true);
  assert.throws(() => A.validateV3Contact(badEk));
  // Format errors, legacy contacts and junk.
  assert.throws(() => A.validateV3Contact({ ...fromCard, mldsaHash: "00".repeat(32) }), /Not a valid R1DO v3 contact/);
  assert.throws(() => A.validateV3Contact({ name: "old", publicKey: V2.identityA.publicKeyHex }), /Not a valid/);
  assert.throws(() => A.validateV3Contact(null), /Not a valid/);
});

test("base45: RFC 9285 examples and strict decoding", () => {
  const ex = [["AB", "BB8"], ["Hello!!", "%69 VD92EX0"], ["base-45", "UJCLQE7W581"], ["ietf!", "QED8WEX0"], ["", ""]];
  for (const [plain, enc] of ex) {
    assert.equal(A.base45Encode(utf8ToBytes(plain)), enc);
    assert.equal(new TextDecoder().decode(A.base45Decode(enc)), plain);
  }
  assert.throws(() => A.base45Decode("GGW"), /not base45/, "65536 is out of range");
  assert.throws(() => A.base45Decode(":::"), /not base45/);
  assert.throws(() => A.base45Decode("U6"), /not base45/, "256 is out of range for a final pair");
  assert.throws(() => A.base45Decode("BB8A"), /not base45/, "dangling character");
  assert.throws(() => A.base45Decode("bb8"), /not base45/, "lower case is not base45");
  assert.throws(() => A.base45Decode("BB8", 3), /expected 3 bytes, got 2/);
});

test("QR text: base45 round trip, QR alphanumeric charset and size", async () => {
  for (const prf of [prfA, prfB]) {
    const id = await A.deriveIdentityV3(prf());
    const text = A.encodeQrText(id);
    assert.ok(text.startsWith("R1DO-QR-V3:"));
    assert.equal(text.length, 11 + (A.QR_BYTES / 2) * 3); // 1943
    assert.match(text, /^[0-9A-Z $%*+\-./:]+$/, "only QR alphanumeric characters");
    assert.deepEqual(A.base45Decode(text.slice(11)), A.encodeQrPayload(id));
    assert.deepEqual(A.decodeQrPayload(text), A.decodeQrPayload(A.encodeQrPayload(id)));
    // copy-paste line breaks are tolerated; a lost space (a base45 digit) is not
    const fromQr = A.parsePublicIdentity(text);
    assert.deepEqual(A.parsePublicIdentity(`  ${text.slice(0, 40)}\r\n${text.slice(40)}\n`), fromQr);
    if (text.slice(11).includes(" ")) assert.throws(() => A.parsePublicIdentity(text.replace(/ /g, "")));
  }
  const text = V3.identityA.qrText;
  assert.ok(text.slice(11).includes(" "), "the vector exercises a space digit");
  assert.throws(() => A.decodeQrPayload(text.slice(0, -1)), /not base45/);
  assert.throws(() => A.decodeQrPayload(text.slice(0, -3)), /expected 1288 bytes/);
  assert.throws(() => A.decodeQrPayload(text.slice(0, -1) + "a"), /not base45/);
  assert.throws(() => A.decodeQrPayload(text.toLowerCase()), /Not an R1DO v3 QR payload/);
  // the pre-release base64url form ("r1do-qr-v3:...") is gone
  const id = await A.deriveIdentityV3(prfA());
  assert.throws(() => A.parsePublicIdentity("r1do-qr-v3:" + A.b64urlEncode(A.encodeQrPayload(id))), /Expected an R1DO v3 card/);

  // The vendored qrcode.js puts the whole text in ONE alphanumeric segment:
  // version 26 at error correction L, 30 at M (base64url in byte mode was 30-L, 35-M).
  const segs = [{ data: text, mode: "alphanumeric" }];
  const atL = QRCode.create(segs, { errorCorrectionLevel: "L" });
  const atM = QRCode.create(segs, { errorCorrectionLevel: "M" });
  assert.equal(atL.segments.length, 1);
  assert.equal(atL.segments[0].mode.id, "Alphanumeric");
  assert.deepEqual([atL.version, atL.modules.size], [26, 121]);
  assert.deepEqual([atM.version, atM.modules.size], [30, 137]);
});

test("ECIES v3: v2 and unknown envelope versions are rejected with a clear error", async () => {
  const b = await A.deriveIdentityV3(prfB());
  await assert.rejects(A.decryptAnyEnvelope({ envelope: V2.ecies.envelope, myIdentity: b }), (e) => {
    assert.equal(e.message, A.V2_ENVELOPE_ERROR);
    assert.equal(e.code, "R1DO_ENVELOPE_V2");
    return true;
  });
  await assert.rejects(A.decryptAnyEnvelope({ envelope: { ...V3.ecies.envelope, v: 4 }, myIdentity: b }), /Unsupported/);
  await assert.rejects(A.decryptAnyEnvelope({ envelope: null, myIdentity: b }), /Not an R1DO envelope/);
});
