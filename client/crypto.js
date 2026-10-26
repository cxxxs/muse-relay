/* Muse Relay client crypto. All key material stays on this device.
 * Counterpart: relay.py (Python). The two must implement identical primitives:
 *   lookup  = b64url( SHA256("muse-relay-v1:lookup:" + code_words)[0:12] )
 *   kek     = PBKDF2-HMAC-SHA256(pw=code_words, salt="muse-relay-v1:wrap:"+lookup,
 *                                600000 rounds, 32 bytes)
 *   wrapped = AES-256-GCM(kek, 12-byte nonce, space_key)
 *   message = AES-256-GCM(space_key, 12-byte nonce,
 *                         JSON {v:1, author, ts, body})
 *   sig     = Ed25519("muse-relay-msg-v1" || space_id_raw || nonce_raw ||
 *                     ciphertext_raw)
 *   control   = Ed25519 keypair minted at creation; control_pub stored
 *               server-side, seed wrapped under the space key.
 *   cert      = Ed25519("muse-relay-member-v1" || space_id_raw ||
 *               member_pubkey_raw || utf8(display_name)) signed by the
 *               control seed. The server verifies certs before adding
 *               members, so it cannot forge participants.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { WORDS } from "./words.js";

const te = new TextEncoder();
const td = new TextDecoder();

export function b64urlEncode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function genCodeWords(n = 8) {
  // 2048 = 2^11, so any 11 bits index the wordlist uniformly — no rejection
  // sampling needed.
  const r = randomBytes(Math.ceil((n * 11) / 8) + 2);
  const out = [];
  let acc = 0, bits = 0, i = 0;
  while (out.length < n) {
    acc = (acc << 8) | r[i++];
    bits += 8;
    while (bits >= 11 && out.length < n) {
      bits -= 11;
      out.push(WORDS[(acc >> bits) & 2047]);
      acc &= (1 << bits) - 1;
    }
  }
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** Fingerprint of the pairing code. Sent to the server for space lookup.
 *  The code words themselves never leave the device. */
export async function deriveLookup(codeWords) {
  const h = await sha256(te.encode("muse-relay-v1:lookup:" + codeWords.join(" ")));
  return b64urlEncode(h.slice(0, 12)); // 96-bit lookup id
}

async function importAesGcm(raw, usages) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

/** Key-encryption key from the pairing code. 600k PBKDF2 rounds make an
 *  offline attack against a stolen wrapped blob infeasible for 88-bit codes. */
export async function deriveKek(codeWords, lookupB64) {
  const pw = await crypto.subtle.importKey(
    "raw", te.encode(codeWords.join(" ")), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: te.encode("muse-relay-v1:wrap:" + lookupB64),
      iterations: 600000, hash: "SHA-256" },
    pw, 256
  );
  return new Uint8Array(bits);
}

/** Wrap the space key for code-based joins. Returns one blob:
 *  b64url(nonce[12] || AES-256-GCM(kek, space_key)). The server stores this
 *  blob but cannot open it — only the code words derive the kek. */
export async function wrapSpaceKey(kek, spaceKey) {
  const nonce = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce },
      await importAesGcm(kek, ["encrypt"]), spaceKey)
  );
  const blob = new Uint8Array(12 + ct.length);
  blob.set(nonce, 0);
  blob.set(ct, 12);
  return b64urlEncode(blob);
}

export async function unwrapSpaceKey(kek, wrappedB64) {
  const blob = b64urlDecode(wrappedB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, 12) },
    await importAesGcm(kek, ["decrypt"]),
    blob.slice(12)
  );
  return new Uint8Array(pt); // 32-byte space key
}

export async function encryptMessage(spaceKey, author, body) {
  const nonce = randomBytes(12);
  const plaintext = te.encode(JSON.stringify({
    v: 1, author, ts: Date.now(), body,
  }));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce },
      await importAesGcm(spaceKey, ["encrypt"]), plaintext)
  );
  return { nonce: b64urlEncode(nonce), ciphertext: b64urlEncode(ct) };
}

export async function decryptMessage(spaceKey, nonceB64, ciphertextB64) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64urlDecode(nonceB64) },
    await importAesGcm(spaceKey, ["decrypt"]),
    b64urlDecode(ciphertextB64)
  );
  const m = JSON.parse(td.decode(pt));
  if (m.v !== 1 || typeof m.author !== "string" || typeof m.body !== "string")
    throw new Error("bad envelope");
  return m;
}

export function genMemberKeypair() {
  const priv = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(priv);
  return { privB64: b64urlEncode(priv), pubB64: b64urlEncode(pub) };
}

/** Space-control keypair. The control public key is stored server-side; the
 *  seed is wrapped under the space key so only key holders can mint member
 *  certificates. The server verifies each certificate before adding a member,
 *  so it cannot forge participants. */
export function genControlKeypair() {
  const seed = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(seed);
  return { seedB64: b64urlEncode(seed), pubB64: b64urlEncode(pub) };
}

/** Derive the control public key from an unwrapped control seed.
 *  The pinning primitive: after unwrapping, the client computes this
 *  itself and must abort if the server's claimed control_pub differs. */
export function controlPubFromSeed(seedB64) {
  return b64urlEncode(ed25519.getPublicKey(b64urlDecode(seedB64)));
}

export async function wrapControlSeed(spaceKey, seedB64) {
  const nonce = randomBytes(12);
  const plaintext = te.encode(JSON.stringify({ v: 1, kind: "control-seed", seed: seedB64 }));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce },
      await importAesGcm(spaceKey, ["encrypt"]), plaintext)
  );
  const blob = new Uint8Array(12 + ct.length);
  blob.set(nonce, 0);
  blob.set(ct, 12);
  return b64urlEncode(blob);
}

export async function unwrapControlSeed(spaceKey, wrappedB64) {
  const blob = b64urlDecode(wrappedB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, 12) },
    await importAesGcm(spaceKey, ["decrypt"]),
    blob.slice(12)
  );
  const m = JSON.parse(td.decode(pt));
  if (m.v !== 1 || m.kind !== "control-seed" || typeof m.seed !== "string")
    throw new Error("bad control seed");
  return m.seed;
}

/** Member certificate: binds space id + member pubkey + display name under
 *  the control key. Clients verify the roster; the server verifies on add. */
function memberCertInput(spaceIdB64, pubB64, displayName) {
  const parts = [
    te.encode("muse-relay-member-v1"),
    b64urlDecode(spaceIdB64),
    b64urlDecode(pubB64),
    te.encode(displayName.trim()),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function signMemberCert(seedB64, spaceIdB64, pubB64, displayName) {
  const sig = ed25519.sign(
    memberCertInput(spaceIdB64, pubB64, displayName), b64urlDecode(seedB64));
  return b64urlEncode(sig);
}

export function verifyMemberCert(controlPubB64, spaceIdB64, pubB64, displayName, certB64) {
  try {
    return ed25519.verify(b64urlDecode(certB64),
      memberCertInput(spaceIdB64, pubB64, displayName), b64urlDecode(controlPubB64));
  } catch {
    return false;
  }
}

function sigInput(spaceIdB64, nonceB64, ciphertextB64) {
  const parts = [
    te.encode("muse-relay-msg-v1"),
    b64urlDecode(spaceIdB64),
    b64urlDecode(nonceB64),
    b64urlDecode(ciphertextB64),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function signMessage(privB64, spaceIdB64, nonceB64, ciphertextB64) {
  const sig = ed25519.sign(sigInput(spaceIdB64, nonceB64, ciphertextB64),
    b64urlDecode(privB64));
  return b64urlEncode(sig);
}

export function verifyMessage(pubB64, spaceIdB64, nonceB64, ciphertextB64, sigB64) {
  try {
    return ed25519.verify(b64urlDecode(sigB64),
      sigInput(spaceIdB64, nonceB64, ciphertextB64), b64urlDecode(pubB64));
  } catch {
    return false;
  }
}

/* ---- Phase 1 (v2): epochs, kick, roster-bound identity ----
 * These mirror relay.py exactly: same domains, same byte layouts, same
 * HKDF parameters. A v1 signature must never verify as v2 or vice versa —
 * the domains differ, so cross-version replay is impossible by
 * construction. The web UI uses these for verification and epoch-key
 * handling; it does not (yet) expose kick/rotate buttons — see
 * PROTOCOL-V2.md. */

export function epochBytes(epoch) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(epoch));
  return new Uint8Array(buf);
}

function sig2Input(spaceIdB64, epoch, nonceB64, ciphertextB64) {
  const parts = [
    te.encode("muse-relay-msg-v2"),
    b64urlDecode(spaceIdB64),
    epochBytes(epoch),
    b64urlDecode(nonceB64),
    b64urlDecode(ciphertextB64),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function kickInput(spaceIdB64, pubB64, epoch) {
  const parts = [
    te.encode("muse-relay-kick-v1"),
    b64urlDecode(spaceIdB64),
    b64urlDecode(pubB64),
    epochBytes(epoch),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function epochInput(spaceIdB64, epoch) {
  const parts = [
    te.encode("muse-relay-epoch-v1"),
    b64urlDecode(spaceIdB64),
    epochBytes(epoch),
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function signMessageV2(privB64, spaceIdB64, epoch, nonceB64, ciphertextB64) {
  const sig = ed25519.sign(sig2Input(spaceIdB64, epoch, nonceB64, ciphertextB64),
    b64urlDecode(privB64));
  return b64urlEncode(sig);
}

export function verifyMessageV2(pubB64, spaceIdB64, epoch, nonceB64, ciphertextB64, sigB64) {
  try {
    return ed25519.verify(b64urlDecode(sigB64),
      sig2Input(spaceIdB64, epoch, nonceB64, ciphertextB64), b64urlDecode(pubB64));
  } catch {
    return false;
  }
}

export function signKick(seedB64, spaceIdB64, pubB64, epoch) {
  const sig = ed25519.sign(kickInput(spaceIdB64, pubB64, epoch), b64urlDecode(seedB64));
  return b64urlEncode(sig);
}

export function verifyKick(controlPubB64, spaceIdB64, pubB64, epoch, sigB64) {
  try {
    return ed25519.verify(b64urlDecode(sigB64),
      kickInput(spaceIdB64, pubB64, epoch), b64urlDecode(controlPubB64));
  } catch {
    return false;
  }
}

export function signEpochBundle(seedB64, spaceIdB64, epoch) {
  const sig = ed25519.sign(epochInput(spaceIdB64, epoch), b64urlDecode(seedB64));
  return b64urlEncode(sig);
}

export function verifyEpochBundle(controlPubB64, spaceIdB64, epoch, sigB64) {
  try {
    return ed25519.verify(b64urlDecode(sigB64),
      epochInput(spaceIdB64, epoch), b64urlDecode(controlPubB64));
  } catch {
    return false;
  }
}

/** A member's X25519 keypair, used only for epoch-key wrapping. Separate
 *  from the Ed25519 signing keypair, exactly as in relay.py. */
export function genXKeypair() {
  const priv = x25519.utils.randomSecretKey();
  const pub = x25519.getPublicKey(priv);
  return { privB64: b64urlEncode(priv), pubB64: b64urlEncode(pub) };
}

export function x25519Shared(privB64, pubB64) {
  return x25519.getSharedSecret(b64urlDecode(privB64), b64urlDecode(pubB64));
}

/** Derive the AES-256-GCM key that wraps one member's copy of an epoch
 *  key. Parameters match relay.py epoch_wrapping_key exactly: HKDF-SHA256,
 *  salt = the domain string, info = space id bytes || epoch (8-byte BE). */
export async function epochWrappingKey(shared, spaceIdB64, epoch) {
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const infoParts = [b64urlDecode(spaceIdB64), epochBytes(epoch)];
  const infoLen = infoParts.reduce((n, p) => n + p.length, 0);
  const info = new Uint8Array(infoLen);
  let o = 0;
  for (const p of infoParts) { info.set(p, o); o += p.length; }
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256",
      salt: te.encode("muse-relay-epoch-v1"), info },
    ikm, 256);
  return new Uint8Array(bits);
}

/** Wrap an epoch key: b64url(nonce[12] || AES-256-GCM(key, epoch_key)). */
export async function wrapEpochKey(wrappingKey, epochKey) {
  const nonce = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce },
      await importAesGcm(wrappingKey, ["encrypt"]), epochKey));
  const blob = new Uint8Array(12 + ct.length);
  blob.set(nonce, 0);
  blob.set(ct, 12);
  return b64urlEncode(blob);
}

export async function unwrapEpochKey(wrappingKey, wrappedB64) {
  const blob = b64urlDecode(wrappedB64);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.slice(0, 12) },
    await importAesGcm(wrappingKey, ["decrypt"]),
    blob.slice(12));
  return new Uint8Array(pt); // 32-byte epoch key
}

export function parseRelayLink(url) {
  const u = new URL(url);
  const m = u.pathname.match(/^\/s\/([A-Za-z0-9_-]{22})$/);
  if (!m) return null;
  const frag = new URLSearchParams(u.hash.slice(1));
  const k = frag.get("k");
  if (!k || !/^[A-Za-z0-9_-]{43}$/.test(k)) return null;
  return { spaceId: m[1], keyB64: k };
}
