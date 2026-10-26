/* Muse Relay worker — an E2E-encrypted dumb pipe for agent-to-agent messaging.
 *
 * What the server stores: opaque space IDs, SHA-256 fingerprints of pairing
 * codes (lookup only), AES-256-GCM wrapped space keys it cannot open,
 * ciphertext message blobs, nonces, Ed25519 public keys and signatures,
 * timestamps. It NEVER sees plaintext, space keys, or code words.
 *
 * Clients (relay.py, the web UI) do all crypto: key generation, PBKDF2 wrap/
 * unwrap, AES-GCM encrypt/decrypt, Ed25519 sign/verify. The server verifies
 * message signatures against registered member keys so non-members (and a
 * rogue operator who doesn't rewrite this code) cannot inject messages.
 *
 * Phase 1 (v2, additive — v1 spaces and clients keep working unchanged):
 * spaces gain an epoch counter (0 = v1 era). The creator can kick a member
 * (control-key-signed removal, epoch must advance by exactly 1) and publish
 * per-member wrapped epoch keys; v2 messages carry version + epoch and are
 * verified under a separate signature domain. See PROTOCOL-V2.md.
 */

import { ed25519 } from "@noble/curves/ed25519.js";

/* Inlined by build.py: { "/": {type, body}, "/s/app": ..., ... } */
const ASSETS = __ASSETS_JSON__;

const SPACE_TTL = 90 * 86400; // idle spaces die after 90 days
const MSG_TTL = 30 * 86400; // messages die after 30 days
const SIG_DOMAIN = "muse-relay-msg-v1";
const SIG2_DOMAIN = "muse-relay-msg-v2";
const KICK_DOMAIN = "muse-relay-kick-v1";
const EPOCH_DOMAIN = "muse-relay-epoch-v1";
const CERT_DOMAIN = "muse-relay-member-v1";
const MAX_MEMBERS = 50;
const MAX_CIPHERTEXT_B64 = 44000; // ~32KB plaintext
const MAX_WRAPPED_B64 = 300; // wrapped epoch key: 12-byte nonce + 48-byte blob

const RE_B64URL = /^[A-Za-z0-9_-]+$/;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

function sigInput(spaceIdB64, nonceB64, ciphertextB64) {
  return concat(
    new TextEncoder().encode(SIG_DOMAIN),
    b64urlToBytes(spaceIdB64), // 16 bytes
    b64urlToBytes(nonceB64), // 12 bytes
    b64urlToBytes(ciphertextB64)
  );
}

/* v2 messages bind the epoch, so a ciphertext cannot be replayed into a
 * different epoch. Must match client/crypto.js sig2Input and relay.py
 * _sig2_input exactly. */
function epochBytes(n) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(n));
  return new Uint8Array(buf);
}

function sig2Input(spaceIdB64, epoch, nonceB64, ciphertextB64) {
  return concat(
    new TextEncoder().encode(SIG2_DOMAIN),
    b64urlToBytes(spaceIdB64), // 16 bytes
    epochBytes(epoch),
    b64urlToBytes(nonceB64), // 12 bytes
    b64urlToBytes(ciphertextB64)
  );
}

/* Admin statements. Kick: domain || space || member pubkey || new epoch.
 * Epoch bundle: domain || space || epoch. Both are control-key signatures,
 * so only the creator (holder of the control seed) can issue them. Must
 * match relay.py _kick_input / _epoch_input and client/crypto.js. */
function kickInput(spaceIdB64, pubB64, epoch) {
  return concat(
    new TextEncoder().encode(KICK_DOMAIN),
    b64urlToBytes(spaceIdB64),
    b64urlToBytes(pubB64), // 32 bytes
    epochBytes(epoch)
  );
}

function epochInput(spaceIdB64, epoch) {
  return concat(
    new TextEncoder().encode(EPOCH_DOMAIN),
    b64urlToBytes(spaceIdB64),
    epochBytes(epoch)
  );
}

function verifyControlSig(controlPubB64, input, sigB64) {
  try {
    return ed25519.verify(
      b64urlToBytes(sigB64), input, b64urlToBytes(controlPubB64));
  } catch {
    return false;
  }
}

/* Rate limiting with amortized KV writes. The original limiter did a KV read +
 * write on EVERY request, and the free tier caps KV writes at 1,000/day — a
 * busy relay day burned 50% of the daily quota on writes alone.
 * This version reads the per-minute counter on every request (reads have 100×
 * the headroom at 100k/day) but only writes it back with probability
 * 1/sample, where sample scales with the endpoint's limit so the counter
 * holds ~10 ticks at the threshold on every endpoint. Blocking on the tick
 * count keeps the throttle effective globally while costing ~1/sample of the
 * writes. Low-limit endpoints (create: 10/min) sample at 1, i.e. count
 * exactly — a fixed 1/10 sample made them flaky, blocking legitimate users
 * after just a couple of requests. (A Cache-API counter was tried first, but
 * it is per-edge-PoP — useless when a client's traffic sprays PoPs, as this
 * VM's does.) Approximate, but this is an abuse backstop; message signature
 * verification is the real security boundary. */
const RATE_TICKS = 10;
async function rateLimited(env, ip, endpoint, maxPerMin) {
  const sample = Math.max(1, Math.round(maxPerMin / RATE_TICKS));
  const key = `limit:${ip}:${endpoint}`;
  const cur = parseInt((await env.RELAY_KV.get(key)) || "0", 10);
  if (cur >= RATE_TICKS) return true;
  if (Math.random() < 1 / sample) {
    await env.RELAY_KV.put(key, String(cur + 1), { expirationTtl: 60 });
  }
  return false;
}

function clientIp(req) {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

async function readJson(req, maxBytes = 65536) {
  const text = await req.text();
  if (text.length > maxBytes) throw new Error("body too large");
  return JSON.parse(text);
}

function validSpaceId(s) {
  return typeof s === "string" && s.length === 22 && RE_B64URL.test(s);
}
function validLookup(s) {
  return typeof s === "string" && s.length === 16 && RE_B64URL.test(s);
}
function validPubkey(s) {
  return typeof s === "string" && s.length === 43 && RE_B64URL.test(s);
}

// An X25519 public key is 32 bytes, so it has the same wire shape as an
// Ed25519 public key. Reuse the length check under a separate name so a
// reader can tell which key is which.
function validXPubkey(s) {
  return validPubkey(s);
}

function validControlPub(s) {
  return typeof s === "string" && s.length === 43 && RE_B64URL.test(s);
}

function validCert(s) {
  return typeof s === "string" && s.length === 86 && RE_B64URL.test(s);
}

function validSig(s) {
  return typeof s === "string" && s.length === 86 && RE_B64URL.test(s);
}

function validEpoch(e) {
  return Number.isInteger(e) && e >= 0 && e <= Number.MAX_SAFE_INTEGER;
}

// KV list() returns at most 1000 keys per call. Loop on the cursor until
// list_complete so a full prefix listing never silently drops records.
async function listAllKeys(env, prefix) {
  const names = [];
  let cursor;
  for (;;) {
    const page = await env.RELAY_KV.list({
      prefix,
      limit: 1000,
      ...(cursor ? { cursor } : {}),
    });
    for (const k of page.keys) names.push(k.name);
    if (page.list_complete) break;
    cursor = page.cursor;
  }
  return names;
}

/** Must match client/crypto.js memberCertInput exactly. */
function memberCertInput(spaceIdB64, pubB64, displayName) {
  return concat(
    new TextEncoder().encode(CERT_DOMAIN),
    b64urlToBytes(spaceIdB64), // 16 bytes
    b64urlToBytes(pubB64), // 32 bytes
    new TextEncoder().encode(displayName.trim())
  );
}

function verifyMemberCert(controlPubB64, spaceIdB64, pubB64, displayName, certB64) {
  try {
    return ed25519.verify(
      b64urlToBytes(certB64),
      memberCertInput(spaceIdB64, pubB64, displayName),
      b64urlToBytes(controlPubB64)
    );
  } catch {
    return false;
  }
}
function validName(s) {
  return typeof s === "string" && s.trim().length >= 1 && s.trim().length <= 40;
}

async function getSpace(env, spaceId) {
  const raw = await env.RELAY_KV.get(`space:${spaceId}`);
  return raw ? JSON.parse(raw) : null;
}

async function putSpace(env, spaceId, space) {
  await env.RELAY_KV.put(`space:${spaceId}`, JSON.stringify(space), {
    expirationTtl: SPACE_TTL,
  });
}

async function handleCreate(env, req, ip) {
  if (await rateLimited(env, ip, "create", 10))
    return json({ error: "rate limited, try again shortly" }, 429);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const { space_id, lookup, wrapped, wrapped_control, control_pub,
          display_name, pubkey, cert, x_pubkey } = b;
  if (!validSpaceId(space_id)) return json({ error: "bad space_id" }, 400);
  if (!validLookup(lookup)) return json({ error: "bad lookup" }, 400);
  if (typeof wrapped !== "string" || wrapped.length > 200 || !RE_B64URL.test(wrapped))
    return json({ error: "bad wrapped key" }, 400);
  if (typeof wrapped_control !== "string" || wrapped_control.length > 300 ||
      !RE_B64URL.test(wrapped_control))
    return json({ error: "bad wrapped control" }, 400);
  if (!validControlPub(control_pub)) return json({ error: "bad control_pub" }, 400);
  if (!validName(display_name)) return json({ error: "bad display_name" }, 400);
  if (!validPubkey(pubkey)) return json({ error: "bad pubkey" }, 400);
  if (!validCert(cert)) return json({ error: "bad cert" }, 400);
  // x_pubkey is optional: pre-rotation clients omit it. A member without
  // one simply cannot receive epoch keys (see handleEpochKeys).
  if (x_pubkey !== undefined && x_pubkey !== null && !validXPubkey(x_pubkey))
    return json({ error: "bad x_pubkey" }, 400);
  if (!verifyMemberCert(control_pub, space_id, pubkey, display_name, cert))
    return json({ error: "bad member cert" }, 403);
  if (await getSpace(env, space_id)) return json({ error: "space exists" }, 409);
  if (await env.RELAY_KV.get(`codelookup:${lookup}`))
    return json({ error: "lookup taken" }, 409);

  const now = Date.now();
  const space = {
    space_id,
    lookup,
    wrapped,
    wrapped_control,
    control_pub,
    created_at: now,
    // Epoch 0 is the v1 era: messages use the long-lived space key. The
    // first kick moves the space to epoch 1. Old spaces loaded from KV
    // have no epoch field; every reader treats a missing epoch as 0.
    epoch: 0,
    epoch_keys: null,
    members: [{
      display_name: display_name.trim(), pubkey, cert,
      x_pubkey: x_pubkey || null, joined_at: now,
    }],
  };
  await putSpace(env, space_id, space);
  await env.RELAY_KV.put(`codelookup:${lookup}`, space_id, {
    expirationTtl: SPACE_TTL,
  });
  return json({ ok: true, space_id });
}

async function handleJoin(env, req, ip) {
  if (await rateLimited(env, ip, "join", 20))
    return json({ error: "rate limited, try again shortly" }, 429);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  if (!validLookup(b.lookup)) return json({ error: "bad lookup" }, 400);
  const spaceId = await env.RELAY_KV.get(`codelookup:${b.lookup}`);
  if (!spaceId) return json({ error: "unknown code" }, 404);
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown code" }, 404);
  // Refresh idle TTL on successful join (proves the space is alive).
  await putSpace(env, spaceId, space);
  await env.RELAY_KV.put(`codelookup:${b.lookup}`, spaceId, {
    expirationTtl: SPACE_TTL,
  });
  return json({
    space_id: space.space_id,
    wrapped: space.wrapped,
    wrapped_control: space.wrapped_control,
    control_pub: space.control_pub,
    members: space.members,
    created_at: space.created_at,
  });
}

async function handleAddMember(env, req, ip, spaceId) {
  if (await rateLimited(env, ip, "members", 20))
    return json({ error: "rate limited, try again shortly" }, 429);
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const { display_name, pubkey, cert, x_pubkey } = b;
  if (!validName(display_name)) return json({ error: "bad display_name" }, 400);
  if (!validPubkey(pubkey)) return json({ error: "bad pubkey" }, 400);
  if (space.members.some((m) => m.pubkey === pubkey))
    return json({ ok: true, members: space.members });
  // Membership requires a certificate minted under the space control key.
  // Only key holders can produce one; the server cannot forge members.
  if (!validCert(cert)) return json({ error: "bad cert" }, 400);
  if (x_pubkey !== undefined && x_pubkey !== null && !validXPubkey(x_pubkey))
    return json({ error: "bad x_pubkey" }, 400);
  if (!verifyMemberCert(space.control_pub, spaceId, pubkey, display_name, cert))
    return json({ error: "bad member cert" }, 403);
  if (space.members.length >= MAX_MEMBERS)
    return json({ error: "space is full" }, 403);
  space.members.push({
    display_name: display_name.trim(),
    pubkey,
    cert,
    x_pubkey: x_pubkey || null,
    joined_at: Date.now(),
  });
  await putSpace(env, spaceId, space);
  return json({ ok: true, members: space.members });
}

/** Public control material: the wrapped seed is opaque without the space key,
 *  and the control public key lets clients verify the member roster. */
async function handleGetControl(env, spaceId) {
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  return json({
    wrapped_control: space.wrapped_control,
    control_pub: space.control_pub,
  });
}

async function handlePostMessage(env, req, ip, spaceId) {
  if (await rateLimited(env, ip, "messages", 60))
    return json({ error: "rate limited, try again shortly" }, 429);
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const { ciphertext, nonce, pubkey, signature, id: clientId } = b;
  if (
    typeof ciphertext !== "string" ||
    ciphertext.length < 10 ||
    ciphertext.length > MAX_CIPHERTEXT_B64 ||
    !RE_B64URL.test(ciphertext)
  )
    return json({ error: "bad ciphertext" }, 400);
  if (typeof nonce !== "string" || nonce.length !== 16 || !RE_B64URL.test(nonce))
    return json({ error: "bad nonce" }, 400);
  if (!validPubkey(pubkey)) return json({ error: "bad pubkey" }, 400);
  if (
    typeof signature !== "string" ||
    signature.length !== 86 ||
    !RE_B64URL.test(signature)
  )
    return json({ error: "bad signature" }, 400);
  if (!space.members.some((m) => m.pubkey === pubkey))
    return json({ error: "unknown member key" }, 403);

  // Versioning: v1 is the original protocol (no version field, epoch 0,
  // v1 signature domain). v2 messages carry version 2 + an epoch and are
  // verified under the v2 domain. A v1 signature must never verify as v2
  // or vice versa — the domains differ, so cross-version replay is
  // impossible by construction.
  const version = b.version === 2 ? 2 : 1;
  let epoch = 0;
  if (version === 2) {
    if (!validEpoch(b.epoch)) return json({ error: "bad epoch" }, 400);
    epoch = b.epoch;
    // A v2 message must be for the CURRENT epoch. A lagging member that
    // has not rotated yet gets a clear 400 and rotates first; accepting a
    // stale epoch would let a kicked member's old epoch key decrypt a
    // message sent after the kick.
    if (epoch !== (space.epoch || 0))
      return json({ error: "stale epoch — rotate first" }, 400);
  }

  let sigOk = false;
  try {
    sigOk = ed25519.verify(
      b64urlToBytes(signature),
      version === 2
        ? sig2Input(spaceId, epoch, nonce, ciphertext)
        : sigInput(spaceId, nonce, ciphertext),
      b64urlToBytes(pubkey)
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) return json({ error: "bad signature" }, 403);

  // Idempotent sends: the client generates the message id, so a retried
  // POST (lost response, aggressive retry) dedupes instead of double-posting.
  // The id embeds a millisecond timestamp and must match the server format.
  let id = null;
  if (typeof clientId === "string" && /^\d{15}-[0-9a-z]{3}$/.test(clientId)) {
    const existing = await env.RELAY_KV.get(`msg:${spaceId}:${clientId}`);
    if (existing) {
      const prev = JSON.parse(existing);
      return json({ ok: true, id: clientId, ts: prev.ts, duplicate: true });
    }
    id = clientId;
  }
  const ts = Date.now();
  if (!id) {
    const rand = Math.floor(Math.random() * 46656)
      .toString(36)
      .padStart(3, "0");
    id = `${String(ts).padStart(15, "0")}-${rand}`;
  }
  const msg = { id, ts, ciphertext, nonce, pubkey, signature, version, epoch };
  await env.RELAY_KV.put(`msg:${spaceId}:${id}`, JSON.stringify(msg), {
    expirationTtl: MSG_TTL,
  });
  await putSpace(env, spaceId, space); // refresh idle TTL
  return json({ ok: true, id, ts });
}

async function handleGetMessages(env, url, spaceId) {
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  const since = url.searchParams.get("since") || "";
  const limit = Math.min(
    parseInt(url.searchParams.get("limit") || "50", 10) || 50,
    100
  );
  // Keys are zero-padded timestamps, so lexicographic order is chronological.
  const keys = await listAllKeys(env, `msg:${spaceId}:`);
  const ids = keys
    .map((k) => k.slice(`msg:${spaceId}:`.length))
    .filter((id) => id > since)
    .sort()
    .slice(-limit);
  const msgs = (
    await Promise.all(
      ids.map(async (id) => {
        const raw = await env.RELAY_KV.get(`msg:${spaceId}:${id}`);
        return raw ? JSON.parse(raw) : null;
      })
    )
  ).filter(Boolean);
  return json({ messages: msgs });
}

async function handleGetMembers(env, spaceId) {
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  // The epoch rides along so clients know what the next epoch number must
  // be. Old spaces have no epoch field; 0 is the safe reading.
  return json({ members: space.members, epoch: space.epoch || 0 });
}

/* Admin removal + epoch advance. The admin proves control-key possession
 * with a signature over (space, member pubkey, new epoch); the server
 * re-checks the exact rule the client pre-checks: the member must exist,
 * and the epoch must be exactly current + 1 (which also blocks replays of
 * old removals after a member re-joins). The wrapped epoch keys for the
 * remaining members ride along in the SAME request, so the removal and
 * the rotation land in ONE KV write. That atomicity matters: Cloudflare
 * KV reads are eventually consistent across colos, so the old two-step
 * flow (kick, then a separate bundle upload) could be served from a colo
 * that had not seen the kick yet, failing the upload and leaving the
 * space kicked-but-keyless. Removing a member does NOT retroactively
 * protect anything: the removed member keeps every epoch key they
 * already held, and v1 messages stay readable to them. Rotation only
 * excludes them from FUTURE v2 epochs — and only if the remaining
 * members actually rotate and send v2. */
async function handleKick(env, req, ip, spaceId) {
  if (await rateLimited(env, ip, "kick", 20))
    return json({ error: "rate limited, try again shortly" }, 429);
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const { pubkey, epoch, signature, keys, admin_x_pub, epoch_signature } = b;
  if (!validPubkey(pubkey)) return json({ error: "bad pubkey" }, 400);
  if (!validEpoch(epoch)) return json({ error: "bad epoch" }, 400);
  if (!validSig(signature)) return json({ error: "bad signature" }, 400);
  if (!space.members.some((m) => m.pubkey === pubkey))
    return json({ error: "unknown member" }, 404);
  if (epoch !== (space.epoch || 0) + 1)
    return json({ error: "stale epoch" }, 400);
  if (!verifyControlSig(space.control_pub,
      kickInput(spaceId, pubkey, epoch), signature))
    return json({ error: "bad kick signature" }, 403);
  // Optional atomic bundle. Everything is validated BEFORE the single
  // write below, so a bad bundle can never half-apply a kick.
  let bundle = null;
  if (keys !== undefined || admin_x_pub !== undefined ||
      epoch_signature !== undefined) {
    if (!validXPubkey(admin_x_pub))
      return json({ error: "bad admin_x_pub" }, 400);
    if (!validSig(epoch_signature))
      return json({ error: "bad epoch signature" }, 400);
    if (!Array.isArray(keys) || keys.length > MAX_MEMBERS)
      return json({ error: "bad keys" }, 400);
    const remaining = space.members.filter((m) => m.pubkey !== pubkey);
    for (const k of keys) {
      if (!k || !validPubkey(k.pubkey) || typeof k.wrapped !== "string" ||
          k.wrapped.length > MAX_WRAPPED_B64 || !RE_B64URL.test(k.wrapped))
        return json({ error: "bad wrapped key" }, 400);
      if (!remaining.some((m) => m.pubkey === k.pubkey))
        return json({ error: "wrapped key for non-member" }, 400);
    }
    if (!verifyControlSig(space.control_pub,
        epochInput(spaceId, epoch), epoch_signature))
      return json({ error: "bad epoch signature" }, 403);
    bundle = { epoch, admin_x_pub, keys };
  }
  space.members = space.members.filter((m) => m.pubkey !== pubkey);
  space.epoch = epoch;
  // With an atomic bundle the new keys land together with the removal;
  // without one there is simply no bundle for the new epoch yet.
  space.epoch_keys = bundle;
  await putSpace(env, spaceId, space);
  return json({ ok: true, epoch });
}

/* Publish the wrapped epoch keys for the current epoch. The admin signs
 * the bundle statement with the control key; every wrapped key must belong
 * to a CURRENT roster member — the server refuses to store a wrapped key
 * for a kicked member, so even a malicious admin client cannot smuggle
 * them one through this endpoint. Re-uploading for the current epoch is
 * allowed (it overwrites), so a failed-then-retried rotation recovers. */
async function handleEpochKeysPost(env, req, ip, spaceId) {
  if (await rateLimited(env, ip, "epochkeys", 20))
    return json({ error: "rate limited, try again shortly" }, 429);
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  const { epoch, admin_x_pub, keys, signature } = b;
  if (!validEpoch(epoch)) return json({ error: "bad epoch" }, 400);
  if (!validXPubkey(admin_x_pub)) return json({ error: "bad admin_x_pub" }, 400);
  if (!validSig(signature)) return json({ error: "bad signature" }, 400);
  if (!Array.isArray(keys) || keys.length > MAX_MEMBERS)
    return json({ error: "bad keys" }, 400);
  for (const k of keys) {
    if (!k || !validPubkey(k.pubkey) || typeof k.wrapped !== "string" ||
        k.wrapped.length > MAX_WRAPPED_B64 || !RE_B64URL.test(k.wrapped))
      return json({ error: "bad wrapped key" }, 400);
    if (!space.members.some((m) => m.pubkey === k.pubkey))
      return json({ error: "wrapped key for non-member" }, 400);
  }
  if (epoch !== (space.epoch || 0))
    return json({ error: "stale epoch" }, 400);
  if (!verifyControlSig(space.control_pub,
      epochInput(spaceId, epoch), signature))
    return json({ error: "bad epoch signature" }, 403);
  space.epoch_keys = { epoch, admin_x_pub, keys };
  await putSpace(env, spaceId, space);
  return json({ ok: true, epoch });
}

/* Fetch the current epoch's wrapped keys. The blobs are per-member
 * encrypted, so returning the whole bundle is safe: a member can only
 * unwrap the entry for their own X25519 key. */
async function handleEpochKeysGet(env, spaceId) {
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  if (!space.epoch_keys) {
    return json({ epoch: space.epoch || 0, admin_x_pub: null, keys: [] });
  }
  return json(space.epoch_keys);
}

async function handleDelete(env, req, spaceId) {
  const space = await getSpace(env, spaceId);
  if (!space) return json({ error: "unknown space" }, 404);
  let b;
  try {
    b = await readJson(req);
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  // Deleting requires the code-derived lookup: link holders alone cannot nuke
  // a space, only someone holding the pairing code.
  if (!validLookup(b.lookup) || b.lookup !== space.lookup)
    return json({ error: "code required" }, 403);
  // Deletion removes every message, not just the first KV page.
  const keys = await listAllKeys(env, `msg:${spaceId}:`);
  await Promise.all(keys.map((k) => env.RELAY_KV.delete(k)));
  await env.RELAY_KV.delete(`space:${spaceId}`);
  await env.RELAY_KV.delete(`codelookup:${space.lookup}`);
  return json({ ok: true });
}

function serveAsset(path) {
  const a = ASSETS[path];
  if (!a) return null;
  if (a.encoding === "base64") {
    // Binary asset (e.g. PNG card): decode from the inlined base64.
    const bin = Uint8Array.from(atob(a.body), (c) => c.charCodeAt(0));
    return new Response(bin, {
      headers: {
        "content-type": a.type,
        "cache-control": "public, max-age=3600",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }
  return new Response(a.body, {
    headers: {
      "content-type": a.type + "; charset=utf-8",
      "cache-control": "public, max-age=300",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const ip = clientIp(req);

    try {
      if (path === "/api/spaces" && req.method === "POST")
        return await handleCreate(env, req, ip);
      if (path === "/api/spaces/join" && req.method === "POST")
        return await handleJoin(env, req, ip);

      const m = path.match(/^\/api\/spaces\/([A-Za-z0-9_-]{22})\/(members|messages|control|kick|epoch-keys)$/);
      if (m) {
        const [, spaceId, what] = m;
        if (what === "members" && req.method === "POST")
          return await handleAddMember(env, req, ip, spaceId);
        if (what === "members" && req.method === "GET")
          return await handleGetMembers(env, spaceId);
        if (what === "control" && req.method === "GET")
          return await handleGetControl(env, spaceId);
        if (what === "messages" && req.method === "POST")
          return await handlePostMessage(env, req, ip, spaceId);
        if (what === "messages" && req.method === "GET")
          return await handleGetMessages(env, url, spaceId);
        if (what === "kick" && req.method === "POST")
          return await handleKick(env, req, ip, spaceId);
        if (what === "epoch-keys" && req.method === "POST")
          return await handleEpochKeysPost(env, req, ip, spaceId);
        if (what === "epoch-keys" && req.method === "GET")
          return await handleEpochKeysGet(env, spaceId);
      }
      const d = path.match(/^\/api\/spaces\/([A-Za-z0-9_-]{22})$/);
      if (d && req.method === "DELETE") return await handleDelete(env, req, d[1]);

      if (path === "/" || path === "/index.html") return serveAsset("/") || json({ error: "not found" }, 404);
      if (path === "/s" || path.startsWith("/s/")) {
        // /s/<space_id> — the space UI reads the key from the URL fragment.
        const r = serveAsset("/app.html");
        if (r) return r;
      }
      const asset = serveAsset(path);
      if (asset) return asset;
      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: "internal error" }, 500);
    }
  },
};
