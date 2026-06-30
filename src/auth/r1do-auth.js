/* ════════════════════════════════════════════════════════════════════
   r1do-auth.js — shared auth + key-derivation module for the R1DO suite
   (notes.html · tasks.html · chat.html · R1DO Wallet)

   One passkey per user (resident, PRF-capable) unlocks every tool.
   All keys derive from a single PRF evaluation (salt "r1do-suite-v1")
   through real HKDF-SHA256 with per-app `info` labels, so each tool
   gets an independent key tree from the same credential.

   Credential store: IndexedDB "R1DOToolsDB".
   ════════════════════════════════════════════════════════════════════ */

import { p256 } from "./noble-curves-p256.js";
import { sha256 } from "./noble-hashes-sha256.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "./noble-hashes-utils.js";

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

const HKDF_SALT = utf8ToBytes("r1do/hkdf-salt/v2");
const ECIES_SALT = utf8ToBytes("r1do/ecies-salt/v2");
const ECIES_INFO = utf8ToBytes("r1do/ecies-aead/v2");
const ECIES_SIG_TAG = utf8ToBytes("r1do/ecies-sig/v2");

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

/* ───────────── ECIES v2 (ephemeral ECDH + sender signature) ──────── */
/* Fixes over v1: real HKDF, x-only shared secret, and — crucially —
   sender authentication: the envelope is signed with the sender's
   identity key, binding sender → ciphertext → recipient. */

function _eciesKeyMaterial(sharedX) {
    return hkdfAesKeyFromRaw(sharedX);
}

async function hkdfAesKeyFromRaw(sharedX) {
    const key = await _importIkm(sharedX);
    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: ECIES_SALT,
            info: ECIES_INFO,
        },
        key,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );
}

function _sigDigest(epk, iv, ct, recipientPub) {
    return sha256(concatBytes(ECIES_SIG_TAG, epk, iv, ct, recipientPub));
}

export async function eciesEncrypt({
    message,
    recipientPublicKeyHex,
    senderPrivateKey,
    senderPublicKeyHex,
}) {
    const recipientPub = hexToBytes(recipientPublicKeyHex);

    const ephPriv = p256.utils.randomPrivateKey();
    const ephPub = p256.getPublicKey(ephPriv, false);

    // x-only shared secret (33B compressed point, drop the prefix byte)
    const sharedX = p256.getSharedSecret(ephPriv, recipientPub, true).slice(1);
    const aesKey = await _eciesKeyMaterial(sharedX);
    zeroize(sharedX);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            aesKey,
            utf8ToBytes(message),
        ),
    );
    zeroize(ephPriv);

    const digest = _sigDigest(ephPub, iv, ct, recipientPub);
    const sig = p256.sign(digest, senderPrivateKey).toCompactRawBytes();

    return {
        v: 2,
        epk: bytesToHex(ephPub),
        iv: Array.from(iv),
        ct: Array.from(ct),
        spk: senderPublicKeyHex,
        sig: bytesToHex(sig),
        ts: new Date().toISOString(),
    };
}

/**
 * Decrypt a v2 envelope. Returns { text, senderPublicKeyHex, verified }.
 * `verified` is the signature check only — the CALLER decides whether
 * `senderPublicKeyHex` belongs to a trusted contact.
 */
export async function eciesDecrypt({ envelope, myPrivateKey }) {
    const ephPub = hexToBytes(envelope.epk);
    const iv = new Uint8Array(envelope.iv);
    const ct = new Uint8Array(envelope.ct);

    const sharedX = p256
        .getSharedSecret(myPrivateKey, ephPub, true)
        .slice(1);
    const aesKey = await _eciesKeyMaterial(sharedX);
    zeroize(sharedX);

    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    const text = new TextDecoder().decode(pt);

    let verified = false;
    try {
        const myPub = p256.getPublicKey(myPrivateKey, false);
        const digest = _sigDigest(ephPub, iv, ct, myPub);
        verified = p256.verify(
            hexToBytes(envelope.sig),
            digest,
            hexToBytes(envelope.spk),
        );
    } catch {
        verified = false;
    }

    return { text, senderPublicKeyHex: envelope.spk ?? null, verified };
}

/** Decrypt a v2 signed envelope. (Pre-v2 envelopes are no longer supported.) */
export async function decryptAnyEnvelope({ envelope, myPrivateKey }) {
    return eciesDecrypt({ envelope, myPrivateKey });
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
