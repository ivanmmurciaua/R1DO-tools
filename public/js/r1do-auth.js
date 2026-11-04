/* ════════════════════════════════════════════════════════════════════
   r1do-auth.js — shared auth + key-derivation module for the R1DO suite
   (notes.html · tasks.html · chat.html · R1DO Wallet)

   One passkey per user (PRF-capable; discoverable by default, or device-bound) unlocks every tool.
   All keys derive from a single PRF evaluation (salt "r1do-suite-v1")
   through real HKDF-SHA256 with per-app `info` labels, so each tool
   gets an independent key tree from the same credential.

   Credential store: IndexedDB "R1DOToolsDB".

   Crypto v3 (post-quantum hybrid, notes sharing + chat):
   - Identity: the v2 P-256 key PLUS an ML-KEM-768 key (encryption) and
     an ML-DSA-44 key (signatures), all derived from the same PRF.
   - Public card "r1do-id-v3:..." carries the three public keys; the QR
     payload replaces the ML-DSA key with its SHA-256 and is written in
     base45 ("R1DO-QR-V3:...", QR alphanumeric mode) to stay scannable.
   - Envelope v3: AES-256-GCM key from P-256 ECDH AND ML-KEM-768 (secure
     if either holds), signed with ECDSA P-256 AND ML-DSA-44 (verified
     only if both hold) over a digest that binds both sender keys. v2
     envelopes are retired and rejected.
   At-rest keys (notes/tasks/contacts DEKs) are unchanged from v2.
   ════════════════════════════════════════════════════════════════════ */

import { p256 } from "./noble-curves-p256.js";
import { sha256 } from "./noble-hashes-sha256.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "./noble-hashes-utils.js";
import { ml_kem768, ml_dsa44 } from "./noble-post-quantum-0.7.1.js";

/* ──────────────────────────── constants ──────────────────────────── */

export const DB_NAME = "R1DOToolsDB";
export const STORE_NAME = "credentials";
const DB_VERSION = 1;

// Unified PRF salt for the whole suite. Per-app isolation happens at the
// HKDF `info` level — equivalent separation, and a same-origin attacker
// could request any PRF salt anyway, so per-app salts add nothing.
export const PRF_SALT_SUITE = "r1do-suite-v1";

// HKDF domain-separation labels (one sub-tree per purpose).
export const INFO = {
    ID_P256: "r1do/id-p256/v2", // shared identity for notes + chat (ECIES, signatures)
    NOTES_DEK: "r1do/notes/dek/v2", // notes at rest
    TASKS_DEK: "r1do/tasks/dek/v2", // tasks/projects/sessions at rest
    CONTACTS_DEK: "r1do/contacts/dek/v2", // contact list at rest (shared notes + chat)
    WALLET_ROOT: "r1do/wallet/root/v2", // reserved: R1DO Wallet key tree
};

// v3 labels for the post-quantum identity keys. Kept out of INFO on
// purpose: INFO is the frozen v2 set (test/vectors.json pins it as a whole).
export const INFO_V3 = {
    ID_MLKEM: "r1do/id-mlkem768/v3", // 64-byte ML-KEM-768 keygen seed
    ID_MLDSA: "r1do/id-mldsa44/v3", // 32-byte ML-DSA-44 keygen seed
};

const HKDF_SALT = utf8ToBytes("r1do/hkdf-salt/v2");
const ECIES_SALT_V3 = utf8ToBytes("r1do/ecies-salt/v3");
const ECIES_INFO_V3 = utf8ToBytes("r1do/ecies-aead/v3");
const ECIES_SIG_TAG_V3 = utf8ToBytes("r1do/ecies-sig/v3");

// Public card / QR payload layout (binary, before the text encoding).
const CARD_MAGIC = utf8ToBytes("R1DOID3");
const QR_MAGIC = utf8ToBytes("R1DOQR3");
export const CARD_PREFIX = "r1do-id-v3:";
// Upper case on purpose: the whole QR text (prefix + base45) fits the QR
// alphanumeric charset (0-9 A-Z space $%*+-./:), 5.5 bits per character.
export const QR_PREFIX = "R1DO-QR-V3:";
const LEN = {
    P256_PUB: 65,
    MLKEM_EK: ml_kem768.lengths.publicKey, // 1184
    MLKEM_CT: ml_kem768.lengths.cipherText, // 1088
    MLDSA_PK: ml_dsa44.lengths.publicKey, // 1312
    MLDSA_SIG: ml_dsa44.lengths.signature, // 2420
    ECDSA_SIG: 64,
};
export const CARD_BYTES = CARD_MAGIC.length + LEN.P256_PUB + LEN.MLKEM_EK + LEN.MLDSA_PK; // 2568
export const QR_BYTES = QR_MAGIC.length + LEN.P256_PUB + LEN.MLKEM_EK + 32; // 1288

export const V2_ENVELOPE_ERROR =
    "old envelope format (v2): ask the sender to update R1DO";

const CURVE_ORDER_P256 = BigInt(
    "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
);

/* ──────────────────────────── small utils ────────────────────────── */

function concatBytes(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

export function zeroize(u8) {
    if (u8 && typeof u8.fill === "function") u8.fill(0);
}

/** base64url without padding (cards, envelopes). */
export function b64urlEncode(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict base64url decode: rejects bad characters, non-canonical
    encodings and (if given) any length other than `expectedLength`. */
export function b64urlDecode(str, expectedLength = null, what = "value") {
    if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str))
        throw new Error(`Invalid ${what}: not base64url`);
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    let bin;
    try {
        bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    } catch {
        throw new Error(`Invalid ${what}: not base64url`);
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    if (b64urlEncode(out) !== str)
        throw new Error(`Invalid ${what}: non-canonical base64url`);
    if (expectedLength != null && out.length !== expectedLength)
        throw new Error(
            `Invalid ${what}: expected ${expectedLength} bytes, got ${out.length}`,
        );
    return out;
}

function _hexExact(str, length, what) {
    if (typeof str !== "string" || !new RegExp(`^[0-9a-fA-F]{${length * 2}}$`).test(str))
        throw new Error(`Invalid ${what}: expected ${length * 2} hex characters`);
    return hexToBytes(str.toLowerCase());
}

/* Base45 (RFC 9285): 2 bytes -> 3 characters of the QR alphanumeric
   charset, so a QR can carry binary in alphanumeric mode (8.25 bits per
   byte instead of 10.67 for base64 in byte mode). */
const B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

export function base45Encode(u8) {
    let s = "";
    for (let i = 0; i + 1 < u8.length; i += 2) {
        let n = u8[i] * 256 + u8[i + 1];
        for (let k = 0; k < 3; k++, n = Math.floor(n / 45)) s += B45[n % 45];
    }
    if (u8.length % 2) {
        const n = u8[u8.length - 1];
        s += B45[n % 45] + B45[Math.floor(n / 45)];
    }
    return s;
}

/** Strict base45 decode: rejects bad characters, a dangling character,
    out-of-range groups and (if given) any length other than `expectedLength`. */
export function base45Decode(str, expectedLength = null, what = "value") {
    if (typeof str !== "string" || str.length % 3 === 1)
        throw new Error(`Invalid ${what}: not base45`);
    const out = new Uint8Array(Math.floor(str.length / 3) * 2 + (str.length % 3 ? 1 : 0));
    let o = 0;
    for (let i = 0; i < str.length; i += 3) {
        const group = str.slice(i, i + 3);
        let n = 0;
        for (let k = group.length - 1; k >= 0; k--) {
            const d = B45.indexOf(group[k]);
            if (d < 0) throw new Error(`Invalid ${what}: not base45`);
            n = n * 45 + d;
        }
        if (group.length === 3) {
            if (n > 0xffff) throw new Error(`Invalid ${what}: not base45`);
            out[o++] = n >> 8;
            out[o++] = n & 0xff;
        } else {
            if (n > 0xff) throw new Error(`Invalid ${what}: not base45`);
            out[o++] = n;
        }
    }
    if (expectedLength != null && out.length !== expectedLength)
        throw new Error(
            `Invalid ${what}: expected ${expectedLength} bytes, got ${out.length}`,
        );
    return out;
}

function _bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
}

/* ─────────────────── credential store (IndexedDB) ────────────────── */
/* Record format:
   { username, credentialId, credentialIdRaw: number[], prfSupported, createdAt } */

let _db = null;

function _openDB(name, version, upgrade) {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(name, version);
        if (upgrade) req.onupgradeneeded = (e) => upgrade(e.target.result);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

function _getAll(db) {
    return new Promise((resolve, reject) => {
        if (!db.objectStoreNames.contains(STORE_NAME)) return resolve([]);
        const req = db
            .transaction(STORE_NAME, "readonly")
            .objectStore(STORE_NAME)
            .getAll();
        req.onsuccess = () => resolve(req.result ?? []);
        req.onerror = () => reject(req.error);
    });
}

export async function initCredDB() {
    if (_db) return _db;
    _db = await _openDB(DB_NAME, DB_VERSION, (db) => {
        if (!db.objectStoreNames.contains(STORE_NAME)) {
            const store = db.createObjectStore(STORE_NAME, {
                keyPath: "username",
            });
            store.createIndex("credentialId", "credentialId", {
                unique: false,
            });
            store.createIndex("createdAt", "createdAt", { unique: false });
        }
    });
    return _db;
}

export async function saveCredential(
    username,
    credentialId,
    credentialIdRaw,
    prfSupported = true,
) {
    const db = await initCredDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        tx.objectStore(STORE_NAME).put({
            username,
            credentialId,
            credentialIdRaw: Array.from(credentialIdRaw),
            prfSupported,
            createdAt: new Date().toISOString(),
        });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

export async function getCredential(username) {
    const db = await initCredDB();
    return new Promise((resolve, reject) => {
        const req = db
            .transaction(STORE_NAME, "readonly")
            .objectStore(STORE_NAME)
            .get(username);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function listCredentials() {
    const db = await initCredDB();
    return _getAll(db);
}

export async function deleteCredentialById(credentialId) {
    const db = await initCredDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        const store = tx.objectStore(STORE_NAME);
        const req = store.index("credentialId").getKey(credentialId);
        req.onsuccess = () => {
            if (req.result != null) store.delete(req.result);
            resolve();
        };
        req.onerror = () => reject(req.error);
    });
}

export async function importCredentials(credentials) {
    const db = await initCredDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, "readwrite");
        const store = tx.objectStore(STORE_NAME);
        for (const cred of credentials) store.put(cred);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
}

export function deleteDatabases() {
    indexedDB.deleteDatabase(DB_NAME);
    _db = null;
}

/* ───────────────────────── WebAuthn (PRF) ────────────────────────── */

// `deviceBound = true` → NON-discoverable (device-bound, not synced to the cloud;
// requires the rawId/allowCredentials at login — kept in R1DOToolsDB). `false`
// (default) → discoverable/resident (works across *.r1do.com by rpId alone, but
// typically synced). Mirrors the wallet's two paths so the whole suite can choose.
export async function registerPasskey(username, { deviceBound = false } = {}) {
    const userId = utf8ToBytes(username).slice(0, 64); // userHandle = username
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "R1DO Tools", id: window.location.hostname },
            user: { id: userId, name: username, displayName: username },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }],
            authenticatorSelection: deviceBound
                ? {
                      userVerification: "preferred",
                      requireResidentKey: false,
                      residentKey: "discouraged",
                  }
                : {
                      userVerification: "preferred",
                      requireResidentKey: true,
                      residentKey: "required",
                  },
            timeout: 60000,
            attestation: "none",
            extensions: { prf: {} },
        },
    });

    const prfEnabled =
        credential.getClientExtensionResults().prf?.enabled || false;
    if (!prfEnabled) {
        throw new Error(
            "WebAuthn PRF not available. Requires Chrome 132+, Safari 17.4+ or Firefox 130+ over HTTPS/localhost.",
        );
    }

    await saveCredential(
        username,
        credential.id,
        new Uint8Array(credential.rawId),
        true,
    );

    return { credentialId: credential.id, rawId: new Uint8Array(credential.rawId) };
}

/**
 * Authenticate and evaluate the suite PRF.
 *
 * Selection: by `username`, by `credentialId`, or — if neither given —
 * every known credential is offered; with an empty store the allowlist
 * is left empty so resident keys can be discovered (new-device login).
 *
 * Returns { prfOutput, credentialId, username }.
 */
export async function authenticate({
    username = null,
    credentialId = null,
} = {}) {
    const creds = await listCredentials();

    let allowList = [];
    if (username != null) {
        const c = creds.find((c) => c.username === username);
        if (!c) throw new Error(`No credential stored for "${username}"`);
        allowList = [
            { type: "public-key", id: new Uint8Array(c.credentialIdRaw) },
        ];
    } else if (credentialId != null) {
        const c = creds.find((c) => c.credentialId === credentialId);
        if (!c) throw new Error("Credential not found");
        allowList = [
            { type: "public-key", id: new Uint8Array(c.credentialIdRaw) },
        ];
    } else {
        allowList = creds.map((c) => ({
            type: "public-key",
            id: new Uint8Array(c.credentialIdRaw),
        }));
    }

    const evalInputs = { first: utf8ToBytes(PRF_SALT_SUITE) };

    const getOptions = {
        publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            userVerification: "required",
            timeout: 60000,
            extensions: { prf: { eval: evalInputs } },
        },
    };
    if (allowList.length > 0)
        getOptions.publicKey.allowCredentials = allowList;

    const assertion = await navigator.credentials.get(getOptions);

    const results = assertion.getClientExtensionResults().prf?.results;
    if (!results?.first) {
        throw new Error(
            "PRF evaluation failed — this authenticator may not support the PRF extension.",
        );
    }

    const prfOutput = new Uint8Array(results.first);

    // Resolve which credential answered.
    let matched = creds.find((c) => c.credentialId === assertion.id);
    let matchedUsername = matched?.username ?? null;

    // Discovered resident key on a fresh device: learn it from the assertion.
    if (!matched) {
        const handle = assertion.response.userHandle;
        if (handle) {
            try {
                matchedUsername = new TextDecoder().decode(
                    new Uint8Array(handle),
                );
            } catch {
                matchedUsername = null;
            }
        }
        if (matchedUsername) {
            await saveCredential(
                matchedUsername,
                assertion.id,
                new Uint8Array(assertion.rawId),
                true,
            );
        }
    }

    return {
        prfOutput,
        credentialId: assertion.id,
        username: matchedUsername,
    };
}

/* ───────────────────────── HKDF (WebCrypto) ──────────────────────── */

async function _importIkm(ikm) {
    return crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, [
        "deriveKey",
        "deriveBits",
    ]);
}

/** Derive raw bytes: HKDF-SHA256(ikm, salt, info) → Uint8Array(length). */
export async function hkdfBits(ikm, info, length = 32, salt = HKDF_SALT) {
    const key = await _importIkm(ikm);
    const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info: utf8ToBytes(info) },
        key,
        length * 8,
    );
    return new Uint8Array(bits);
}

/** Derive a non-extractable AES-256-GCM key for the given purpose label. */
export async function hkdfAesKey(ikm, info, salt = HKDF_SALT) {
    const key = await _importIkm(ikm);
    return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info: utf8ToBytes(info) },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );
}

/* ─────────────────────── p256 identity (v2) ──────────────────────── */

function _toP256Scalar(seed) {
    // Deterministic rejection sampling into [1, n-1].
    let hash = seed;
    let attempt = 0;
    while (
        BigInt("0x" + bytesToHex(hash)) >= CURVE_ORDER_P256 ||
        BigInt("0x" + bytesToHex(hash)) === 0n
    ) {
        hash = sha256(concatBytes(hash, new Uint8Array([attempt++])));
    }
    return hash;
}

/** Unified notes+chat identity: PRF → HKDF(ID_P256) → p256 keypair. */
export async function deriveP256Identity(prfOutput) {
    const seed = await hkdfBits(prfOutput, INFO.ID_P256, 32);
    const privateKey = _toP256Scalar(seed);
    const publicKey = p256.getPublicKey(privateKey, false); // 65B uncompressed
    return { privateKey, publicKey, publicKeyHex: bytesToHex(publicKey) };
}

/* ──────────────────────── AEAD (AES-256-GCM) ─────────────────────── */

/** Encrypt a UTF-8 string → { v: 2, iv: number[], ct: number[] }. */
export async function aesEncrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        utf8ToBytes(plaintext),
    );
    return { v: 2, iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

/** Decrypt an AES-GCM blob in {iv, ct} shape. */
export async function aesDecrypt(key, blob) {
    const iv = new Uint8Array(blob.iv);
    const ct = new Uint8Array(blob.ct);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new TextDecoder().decode(pt);
}

/* ─────────────── post-quantum identity (v3, additive) ────────────── */

/** PRF → HKDF(ID_MLKEM) 64B seed → ML-KEM-768, HKDF(ID_MLDSA) 32B seed → ML-DSA-44. */
export async function derivePqIdentity(prfOutput) {
    const kemSeed = await hkdfBits(prfOutput, INFO_V3.ID_MLKEM, 64);
    const dsaSeed = await hkdfBits(prfOutput, INFO_V3.ID_MLDSA, 32);
    const kem = ml_kem768.keygen(kemSeed);
    const dsa = ml_dsa44.keygen(dsaSeed);
    zeroize(kemSeed);
    zeroize(dsaSeed);
    return {
        mlkemSecretKey: kem.secretKey,
        mlkemPublicKey: kem.publicKey,
        mldsaSecretKey: dsa.secretKey,
        mldsaPublicKey: dsa.publicKey,
    };
}

/** Full v3 identity: the unchanged v2 P-256 key + the PQ keys. */
export async function deriveIdentityV3(prfOutput) {
    const ec = await deriveP256Identity(prfOutput);
    const pq = await derivePqIdentity(prfOutput);
    return { ...ec, ...pq };
}

/** Wipe every secret of a v3 identity (logout). */
export function zeroizeIdentity(id) {
    if (!id) return;
    zeroize(id.privateKey);
    zeroize(id.mlkemSecretKey);
    zeroize(id.mldsaSecretKey);
}

/* ─────────────────────── public card + QR (v3) ───────────────────── */
/* Card (binary): "R1DOID3" || P-256 pub (65) || ML-KEM ek (1184)
                  || ML-DSA pk (1312), text "r1do-id-v3:" + base64url.
   QR   (binary): "R1DOQR3" || P-256 pub (65) || ML-KEM ek (1184)
                  || sha256(ML-DSA pk) (32), text "R1DO-QR-V3:" + base45
                  (1943 characters, one alphanumeric segment: QR version
                  26 at error correction L, 30 at M).
   The QR is enough to encrypt to someone and to recognise their
   signatures (the envelope carries the full ML-DSA key, checked
   against the hash). */

function _checkP256(pub) {
    if (pub.length !== LEN.P256_PUB || pub[0] !== 0x04)
        throw new Error("Invalid P-256 public key (uncompressed, 65 bytes)");
    p256.ProjectivePoint.fromHex(pub).assertValidity();
}

function _checkMlkem(ek) {
    // encapsulate() runs the FIPS 203 modulus check on the key.
    ml_kem768.encapsulate(ek);
}

function _publics(id) {
    return {
        p256: id.publicKey,
        mlkem: id.mlkemPublicKey,
        mldsa: id.mldsaPublicKey,
    };
}

/** Binary v3 card from an identity (or {publicKey, mlkemPublicKey, mldsaPublicKey}). */
export function encodeCardBytes(id) {
    const { p256: p, mlkem, mldsa } = _publics(id);
    if (p.length !== LEN.P256_PUB || mlkem.length !== LEN.MLKEM_EK || mldsa.length !== LEN.MLDSA_PK)
        throw new Error("encodeCard: wrong key lengths");
    return concatBytes(CARD_MAGIC, p, mlkem, mldsa);
}

export function encodeCard(id) {
    return CARD_PREFIX + b64urlEncode(encodeCardBytes(id));
}

/** Parse + validate a card (text or bytes) → { p256, mlkem, mldsaPk, mldsaHash } (bytes). */
export function decodeCard(input) {
    let bytes = input;
    if (typeof input === "string") {
        const t = input.trim();
        if (!t.startsWith(CARD_PREFIX)) throw new Error("Not an R1DO v3 card");
        bytes = b64urlDecode(t.slice(CARD_PREFIX.length), CARD_BYTES, "card");
    }
    if (!(bytes instanceof Uint8Array) || bytes.length !== CARD_BYTES)
        throw new Error(`Invalid card: expected ${CARD_BYTES} bytes`);
    if (!_bytesEqual(bytes.subarray(0, CARD_MAGIC.length), CARD_MAGIC))
        throw new Error("Invalid card: bad magic");
    let o = CARD_MAGIC.length;
    const p = bytes.slice(o, (o += LEN.P256_PUB));
    const mlkem = bytes.slice(o, (o += LEN.MLKEM_EK));
    const mldsaPk = bytes.slice(o, (o += LEN.MLDSA_PK));
    _checkP256(p);
    _checkMlkem(mlkem);
    return { p256: p, mlkem, mldsaPk, mldsaHash: sha256(mldsaPk) };
}

/** SHA-256 (hex) of the binary card: compare it out of band. */
export function cardFingerprint(card) {
    let bytes = card;
    if (typeof card === "string") {
        decodeCard(card); // validate first
        bytes = b64urlDecode(card.trim().slice(CARD_PREFIX.length));
    }
    return bytesToHex(sha256(bytes));
}

const FP_TAG = utf8ToBytes("R1DOFP3");

/**
 * The fingerprint the UI shows for a person, the same everywhere (own key, contact list, chat):
 * SHA-256 (hex) of "R1DOFP3" || P-256 pub || ML-KEM ek || SHA-256(ML-DSA pk). Unlike
 * cardFingerprint it can also be computed for a contact added from a QR, which only knows the
 * ML-DSA key hash, so a card and a QR of the same identity give the same value. Display only:
 * it is not part of any envelope or signature.
 * Accepts an identity ({ publicKey, mlkemPublicKey, mldsaPublicKey } bytes) or a contact /
 * parsed card or QR ({ p256 hex, mlkem base64url, mldsaHash hex }).
 */
export function identityFingerprint(x) {
    let p, ek, mldsaHash;
    if (x?.mlkemPublicKey != null) {
        const pub = _publics(x);
        p = pub.p256;
        ek = pub.mlkem;
        mldsaHash = sha256(pub.mldsa);
    } else {
        p = _hexExact(x?.p256, LEN.P256_PUB, "p256");
        ek = b64urlDecode(x?.mlkem, LEN.MLKEM_EK, "mlkem");
        mldsaHash = _hexExact(x?.mldsaHash, 32, "mldsaHash");
    }
    return bytesToHex(sha256(concatBytes(FP_TAG, p, ek, mldsaHash)));
}

/** Short, groupable form of a fingerprint for display. */
export function shortFingerprint(hex) {
    return hex.slice(0, 16).match(/.{4}/g).join(" ");
}

export function encodeQrPayload(id) {
    const { p256: p, mlkem, mldsa } = _publics(id);
    return concatBytes(QR_MAGIC, p, mlkem, sha256(mldsa));
}

/** Text form of the QR payload (what a phone camera hands back). Only
    QR alphanumeric characters: render it as an "alphanumeric" segment. */
export function encodeQrText(id) {
    return QR_PREFIX + base45Encode(encodeQrPayload(id));
}

/** Parse + validate a QR payload (bytes or text) → { p256, mlkem, mldsaHash } (bytes). */
export function decodeQrPayload(input) {
    let bytes = input;
    if (typeof input === "string") {
        const t = input.trim();
        if (!t.startsWith(QR_PREFIX)) throw new Error("Not an R1DO v3 QR payload");
        bytes = base45Decode(t.slice(QR_PREFIX.length), QR_BYTES, "QR payload");
    }
    if (!(bytes instanceof Uint8Array) || bytes.length !== QR_BYTES)
        throw new Error(`Invalid QR payload: expected ${QR_BYTES} bytes`);
    if (!_bytesEqual(bytes.subarray(0, QR_MAGIC.length), QR_MAGIC))
        throw new Error("Invalid QR payload: bad magic");
    let o = QR_MAGIC.length;
    const p = bytes.slice(o, (o += LEN.P256_PUB));
    const mlkem = bytes.slice(o, (o += LEN.MLKEM_EK));
    const mldsaHash = bytes.slice(o, o + 32);
    _checkP256(p);
    _checkMlkem(mlkem);
    return { p256: p, mlkem, mldsaHash };
}

/**
 * Card or QR text → the key fields stored in a contact:
 * { p256 (hex), mlkem (base64url), mldsaHash (hex), mldsaPk? (base64url) }.
 * Throws with a readable message on anything else.
 */
export function parsePublicIdentity(text) {
    const raw = String(text ?? "").trim();
    // QR text first: space is a base45 digit there, so only line breaks /
    // tabs from copy-paste are dropped (the last base45 character of an
    // even-length payload is at most "W", so trim() never eats data).
    if (raw.startsWith(QR_PREFIX)) {
        const q = decodeQrPayload(raw.replace(/[\r\n\t]+/g, ""));
        return {
            p256: bytesToHex(q.p256),
            mlkem: b64urlEncode(q.mlkem),
            mldsaHash: bytesToHex(q.mldsaHash),
        };
    }
    const t = raw.replace(/\s+/g, "");
    if (t.startsWith(CARD_PREFIX)) {
        const c = decodeCard(t);
        return {
            p256: bytesToHex(c.p256),
            mlkem: b64urlEncode(c.mlkem),
            mldsaHash: bytesToHex(c.mldsaHash),
            mldsaPk: b64urlEncode(c.mldsaPk),
        };
    }
    if (/^[0-9a-fA-F]{130}$/.test(t))
        throw new Error("That is an old (v2) public key: ask for their R1DO v3 card");
    throw new Error('Expected an R1DO v3 card ("r1do-id-v3:...") or QR text ("R1DO-QR-V3:...")');
}

/** True if a stored contact carries v3 keys (else it is a legacy v2 one). */
export function isV3Contact(c) {
    try {
        if (!c || typeof c !== "object") return false;
        _hexExact(c.p256, LEN.P256_PUB, "p256");
        b64urlDecode(c.mlkem, LEN.MLKEM_EK, "mlkem");
        _hexExact(c.mldsaHash, 32, "mldsaHash");
        if (c.mldsaPk != null) {
            const pk = b64urlDecode(c.mldsaPk, LEN.MLDSA_PK, "mldsaPk");
            if (bytesToHex(sha256(pk)) !== c.mldsaHash.toLowerCase()) return false;
        }
        return true;
    } catch {
        return false;
    }
}

/**
 * Full check of a stored / imported v3 contact, the same one a card or
 * QR gets in parsePublicIdentity: format (isV3Contact) PLUS a valid
 * P-256 point and an ML-KEM key that passes the FIPS 203 modulus check.
 * Returns the normalized key fields { p256, mlkem, mldsaHash, mldsaPk? };
 * throws on anything else.
 */
export function validateV3Contact(c) {
    if (!isV3Contact(c)) throw new Error("Not a valid R1DO v3 contact");
    const p = hexToBytes(c.p256.toLowerCase());
    _checkP256(p);
    _checkMlkem(b64urlDecode(c.mlkem, LEN.MLKEM_EK, "mlkem"));
    const keys = {
        p256: c.p256.toLowerCase(),
        mlkem: c.mlkem,
        mldsaHash: c.mldsaHash.toLowerCase(),
    };
    if (c.mldsaPk != null) keys.mldsaPk = c.mldsaPk;
    return keys;
}

/* ──────── ECIES v3 (hybrid KEM + dual signature, PQ envelope) ─────── */
/* Key: HKDF(ss_ecdh || ss_mlkem, salt, info = label || sha256(epk ||
        kemCt || binding)) → AES-256-GCM, binding = sha256(recipient
        P-256 pub || recipient ek). The transcript is hashed into `info`
        because WebCrypto HKDF caps `info` at 1024 bytes in some engines
        (Node/OpenSSL) and kemCt alone is 1088.
   Sig: ECDSA P-256 AND ML-DSA-44, both by the sender identity, over
        sha256(tag || spk || sha256(spq) || epk || kemCt || iv || ct
        || recipient binding). Field order is fixed; every field except
        ct has a fixed length (65, 32, 65, 1088, 12, ..., 32), so the
        concatenation is unambiguous. spk (sender P-256 pub) and spq
        (sender ML-DSA pk) are in the digest so that each signature also
        vouches for the OTHER sender key: a relay cannot keep the ECDSA
        signature and swap in its own ML-DSA key (or the reverse). */

function _recipientBinding(p256Pub, mlkemEk) {
    return sha256(concatBytes(p256Pub, mlkemEk));
}

async function _hybridAesKey(ikm, epk, kemCt, binding) {
    const key = await _importIkm(ikm);
    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: ECIES_SALT_V3,
            info: concatBytes(ECIES_INFO_V3, sha256(concatBytes(epk, kemCt, binding))),
        },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );
}

/** The signed digest (bytes in, 32 bytes out). Exported so tests and
    independent verifiers can recompute it; not needed to use the API. */
export function sigDigestV3(spk, spq, epk, kemCt, iv, ct, binding) {
    return sha256(
        concatBytes(ECIES_SIG_TAG_V3, spk, sha256(spq), epk, kemCt, iv, ct, binding),
    );
}

/**
 * Encrypt + sign `message` for `recipient` (a v3 contact: { p256 hex,
 * mlkem base64url }) with the sender's v3 identity (deriveIdentityV3).
 */
export async function eciesEncryptV3({ message, recipient, sender }) {
    const rP256 = _hexExact(recipient?.p256, LEN.P256_PUB, "recipient P-256 key");
    const rKem = b64urlDecode(recipient?.mlkem, LEN.MLKEM_EK, "recipient ML-KEM key");
    _checkP256(rP256);
    const binding = _recipientBinding(rP256, rKem);

    const ephPriv = p256.utils.randomPrivateKey();
    const epk = p256.getPublicKey(ephPriv, false);
    // x-only ECDH secret (as v2) + ML-KEM-768 secret
    const ss1 = p256.getSharedSecret(ephPriv, rP256, true).slice(1);
    const { cipherText: kemCt, sharedSecret: ss2 } = ml_kem768.encapsulate(rKem);
    const ikm = concatBytes(ss1, ss2);
    const aesKey = await _hybridAesKey(ikm, epk, kemCt, binding);
    zeroize(ephPriv);
    zeroize(ss1);
    zeroize(ss2);
    zeroize(ikm);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            utf8ToBytes(message),
        ),
    );

    const digest = sigDigestV3(
        sender.publicKey,
        sender.mldsaPublicKey,
        epk,
        kemCt,
        iv,
        ct,
        binding,
    );
    const sig = p256.sign(digest, sender.privateKey).toCompactRawBytes();
    const pqsig = ml_dsa44.sign(digest, sender.mldsaSecretKey);

    return {
        v: 3,
        epk: bytesToHex(epk),
        kem: b64urlEncode(kemCt),
        iv: b64urlEncode(iv),
        ct: b64urlEncode(ct),
        spk: bytesToHex(sender.publicKey),
        spq: b64urlEncode(sender.mldsaPublicKey),
        sig: bytesToHex(sig),
        pqsig: b64urlEncode(pqsig),
        ts: new Date().toISOString(),
    };
}

/**
 * Decrypt a v3 envelope with my v3 identity. Returns { text,
 * senderPublicKeyHex, senderMldsaPk, senderMldsaHash, verified }.
 * `verified` = BOTH signatures valid; the CALLER decides trust (see
 * matchSender). Wrong recipient / tampered ciphertext → throws.
 */
export async function eciesDecryptV3({ envelope, myIdentity }) {
    const epk = _hexExact(envelope.epk, LEN.P256_PUB, "envelope epk");
    const kemCt = b64urlDecode(envelope.kem, LEN.MLKEM_CT, "envelope kem");
    const iv = b64urlDecode(envelope.iv, 12, "envelope iv");
    const ct = b64urlDecode(envelope.ct, null, "envelope ct");
    const spk = _hexExact(envelope.spk, LEN.P256_PUB, "envelope spk");
    const spkHex = bytesToHex(spk);
    const spq = b64urlDecode(envelope.spq, LEN.MLDSA_PK, "envelope spq");
    if (ct.length < 16) throw new Error("Invalid envelope ct: too short");

    const ss1 = p256.getSharedSecret(myIdentity.privateKey, epk, true).slice(1);
    const ss2 = ml_kem768.decapsulate(kemCt, myIdentity.mlkemSecretKey);
    const ikm = concatBytes(ss1, ss2);
    const binding = _recipientBinding(myIdentity.publicKey, myIdentity.mlkemPublicKey);
    const aesKey = await _hybridAesKey(ikm, epk, kemCt, binding);
    zeroize(ss1);
    zeroize(ss2);
    zeroize(ikm);

    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    const text = new TextDecoder().decode(pt);

    const digest = sigDigestV3(spk, spq, epk, kemCt, iv, ct, binding);
    let ecOk = false;
    let pqOk = false;
    try {
        ecOk = p256.verify(
            _hexExact(envelope.sig, LEN.ECDSA_SIG, "envelope sig"),
            digest,
            spk,
        );
    } catch {
        ecOk = false;
    }
    try {
        pqOk = ml_dsa44.verify(
            b64urlDecode(envelope.pqsig, LEN.MLDSA_SIG, "envelope pqsig"),
            digest,
            spq,
        );
    } catch {
        pqOk = false;
    }

    return {
        text,
        senderPublicKeyHex: spkHex,
        senderMldsaPk: envelope.spq,
        senderMldsaHash: bytesToHex(sha256(spq)),
        verified: ecOk === true && pqOk === true,
    };
}

/** Decrypt a shared envelope. Only v3 is accepted; v2 gets a clear error. */
export async function decryptAnyEnvelope({ envelope, myIdentity }) {
    if (!envelope || typeof envelope !== "object")
        throw new Error("Not an R1DO envelope");
    if (envelope.v !== 3) {
        const legacy = envelope.v === 2 || envelope.v === "2";
        const err = new Error(
            legacy ? V2_ENVELOPE_ERROR : "Unsupported R1DO envelope format",
        );
        err.code = legacy ? "R1DO_ENVELOPE_V2" : "R1DO_ENVELOPE_UNKNOWN";
        throw err;
    }
    return eciesDecryptV3({ envelope, myIdentity });
}

/**
 * Sender trust for a decrypt result against a list of v3 contacts:
 * "trusted" (both sigs valid AND spk + sha256(spq) match the contact),
 * "unknown" (both sigs valid, no matching contact) or "invalid".
 */
export function matchSender(result, contacts) {
    if (result.verified !== true) return { trust: "invalid", contact: null };
    const contact =
        (contacts ?? []).find(
            (c) =>
                isV3Contact(c) &&
                c.p256.toLowerCase() === result.senderPublicKeyHex &&
                c.mldsaHash.toLowerCase() === result.senderMldsaHash,
        ) ?? null;
    return { trust: contact ? "trusted" : "unknown", contact };
}

/* ───────────────── contacts (encrypted at rest, shared) ──────────── */

const CONTACTS_KEY_V2 = "contacts_v2";

/** Load the contact list from the encrypted v2 record. */
export async function loadContacts(contactsDek) {
    const v2 = localStorage.getItem(CONTACTS_KEY_V2);
    if (v2) {
        try {
            return JSON.parse(await aesDecrypt(contactsDek, JSON.parse(v2)));
        } catch (e) {
            console.warn("[r1do-auth] contacts_v2 unreadable with this key:", e);
            return [];
        }
    }
    return [];
}

export async function storeContacts(contactsDek, list) {
    const blob = await aesEncrypt(contactsDek, JSON.stringify(list));
    localStorage.setItem(CONTACTS_KEY_V2, JSON.stringify(blob));
}

export function clearContacts() {
    localStorage.removeItem(CONTACTS_KEY_V2);
}
