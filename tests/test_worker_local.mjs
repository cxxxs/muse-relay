// Offline worker tests — no deployment, no network.
//
// Runs the REAL src/worker.js against an in-memory KV mock, so the
// server-side changes in the improvements batch are tested without
// touching the live worker:
// - item 4: rotate-key endpoint (valid / forged / malformed)
// - item 5d: v1 retirement (members without x_pubkey rejected)
// - item 2: duplicate display-name rejection (advisory)
// - item 5a: rotate-epoch endpoint (valid / stale / non-member key)
// - regression: create / add-member / kick still work
//
// Run: node tests/test_worker_local.mjs
//
// The only stub is the __ASSETS_JSON__ placeholder (replaced with {}):
// asset serving is not under test. Everything else is the real code.
// Nothing is printed except PASS/FAIL lines — no keys ever appear.

import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";

const ROOT = new URL("..", import.meta.url).pathname;

// --- load the real worker with only the asset placeholder stubbed ---
// Staged inside the repo tree (not /tmp) so that the worker's
// @noble/curves import resolves from the repo's node_modules. The
// staging dir is removed on process exit, success or failure.
import { rmSync } from "node:fs";
const src = readFileSync(join(ROOT, "src", "worker.js"), "utf8");
if (!src.includes("__ASSETS_JSON__")) {
  throw new Error("worker source no longer carries the asset placeholder");
}
const stubbed = src.replace("__ASSETS_JSON__", "{}");
const dir = mkdtempSync(join(ROOT, "tests", ".worker-tmp-"));
process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
const modPath = join(dir, "worker.mjs");
writeFileSync(modPath, stubbed);
const worker = (await import(pathToFileURL(modPath).href)).default;

// --- helpers (mirror the worker's input constructions exactly) ---
const te = new TextEncoder();
function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
function b64urlDecode(s) {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) out.set(a, o), (o += a.length);
  return out;
}
function epochBytes(n) {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, BigInt(n));
  return new Uint8Array(buf);
}
function randB64url(nbytes, len) {
  return b64url(randomBytes(nbytes)).slice(0, len);
}
function keypair() {
  const priv = randomBytes(32);
  return { priv, pub: b64url(ed25519.getPublicKey(priv)) };
}
function memberCertInput(spaceId, pub, name) {
  return concat(te.encode("muse-relay-member-v1"), b64urlDecode(spaceId),
    b64urlDecode(pub), te.encode(name.trim()));
}
function cert(controlPriv, spaceId, pub, name) {
  return b64url(ed25519.sign(memberCertInput(spaceId, pub, name), controlPriv));
}
function rotateKeyInput(spaceId, wrappedControl, wrapped) {
  return concat(te.encode("muse-relay-rotatekey-v1"), b64urlDecode(spaceId),
    b64urlDecode(wrappedControl), b64urlDecode(wrapped));
}
function epochInput(spaceId, epoch) {
  return concat(te.encode("muse-relay-epoch-v1"), b64urlDecode(spaceId),
    epochBytes(epoch));
}
function kickInput(spaceId, pub, epoch) {
  return concat(te.encode("muse-relay-kick-v1"), b64urlDecode(spaceId),
    b64urlDecode(pub), epochBytes(epoch));
}

// --- in-memory KV mock ---
function makeKv() {
  const map = new Map();
  return {
    async get(k) { return map.has(k) ? map.get(k) : null; },
    async put(k, v) { map.set(k, v); },
    async delete(k) { map.delete(k); },
    async list({ prefix }) {
      const keys = [...map.keys()].filter((k) => k.startsWith(prefix))
        .map((name) => ({ name }));
      return { keys, list_complete: true, cursor: undefined };
    },
  };
}

const env = { RELAY_KV: makeKv() };

async function call(method, path, body) {
  const req = new Request(`https://test${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const res = await worker.fetch(req, env);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, data };
}

// --- test runner ---
const results = [];
function check(name, cond, detail = "") {
  results.push([name, cond]);
  console.log(`[${cond ? "ok" : "FAIL"}] ${name}${!cond && detail ? " — " + detail : ""}`);
}

const spaceId = randB64url(16, 22);
const lookup = randB64url(12, 16);
const control = keypair();
const creator = keypair();
const creatorX = keypair();
const creatorCert = cert(control.priv, spaceId, creator.pub, "creator");

// 1. create with x_pubkey: works.
{
  const r = await call("POST", "/api/spaces", {
    space_id: spaceId, lookup, wrapped: "A".repeat(44),
    wrapped_control: "B".repeat(44), control_pub: control.pub,
    display_name: "creator", pubkey: creator.pub, cert: creatorCert,
    x_pubkey: creatorX.pub,
  });
  check("create with x_pubkey", r.status === 200, JSON.stringify(r.data));
}

// 2. create without x_pubkey: rejected (v1 retirement at creation).
{
  const r = await call("POST", "/api/spaces", {
    space_id: randB64url(16, 22), lookup: randB64url(12, 16),
    wrapped: "A".repeat(44), wrapped_control: "B".repeat(44),
    control_pub: control.pub, display_name: "creator",
    pubkey: creator.pub, cert: creatorCert,
  });
  check("create without x_pubkey rejected", r.status === 400, JSON.stringify(r.data));
}

// 3. add member without x_pubkey: rejected (v1 retirement at join).
{
  const m = keypair();
  const r = await call("POST", `/api/spaces/${spaceId}/members`, {
    display_name: "legacy",
    pubkey: m.pub, cert: cert(control.priv, spaceId, m.pub, "legacy"),
  });
  check("add member without x_pubkey rejected", r.status === 400, JSON.stringify(r.data));
}

// 4. add member with x_pubkey + valid cert: works.
const member = keypair();
const memberX = keypair();
{
  const r = await call("POST", `/api/spaces/${spaceId}/members`, {
    display_name: "member", pubkey: member.pub,
    cert: cert(control.priv, spaceId, member.pub, "member"),
    x_pubkey: memberX.pub,
  });
  check("add member with x_pubkey", r.status === 200, JSON.stringify(r.data));
}

// 5. duplicate display name: rejected (advisory).
{
  const m = keypair();
  const r = await call("POST", `/api/spaces/${spaceId}/members`, {
    display_name: "member", pubkey: m.pub,
    cert: cert(control.priv, spaceId, m.pub, "member"),
    x_pubkey: keypair().pub,
  });
  check("duplicate display name rejected", r.status === 409, JSON.stringify(r.data));
}

// 6. bad cert: rejected.
{
  const m = keypair();
  const other = keypair();
  const r = await call("POST", `/api/spaces/${spaceId}/members`, {
    display_name: "mallory", pubkey: m.pub,
    cert: cert(other.priv, spaceId, m.pub, "mallory"),
    x_pubkey: keypair().pub,
  });
  check("bad member cert rejected", r.status === 403, JSON.stringify(r.data));
}

// 7. rotate-key: valid signature rotates both blobs.
const newWrappedControl = "C".repeat(44);
const newWrapped = "D".repeat(44);
{
  const sig = b64url(ed25519.sign(
    rotateKeyInput(spaceId, newWrappedControl, newWrapped), control.priv));
  const r = await call("POST", `/api/spaces/${spaceId}/rotate-key`, {
    wrapped_control: newWrappedControl, wrapped: newWrapped, signature: sig,
  });
  check("rotate-key valid signature", r.status === 200, JSON.stringify(r.data));
  const c = await call("GET", `/api/spaces/${spaceId}/control`);
  check("rotate-key blobs replaced",
    c.data && c.data.wrapped_control === newWrappedControl);
}
{
  const sig = b64url(ed25519.sign(
    rotateKeyInput(spaceId, "E".repeat(44), "F".repeat(44)), keypair().priv));
  const r = await call("POST", `/api/spaces/${spaceId}/rotate-key`, {
    wrapped_control: "E".repeat(44), wrapped: "F".repeat(44), signature: sig,
  });
  check("rotate-key forged signature rejected", r.status === 403, JSON.stringify(r.data));
}
{
  const r = await call("POST", `/api/spaces/${spaceId}/rotate-key`, {
    wrapped_control: "G".repeat(301), wrapped: "H".repeat(44),
    signature: "I".repeat(86),
  });
  check("rotate-key malformed rejected", r.status === 400, JSON.stringify(r.data));
}

// 8. rotate-epoch: valid advance, then stale, then non-member key.
{
  const sig = b64url(ed25519.sign(epochInput(spaceId, 1), control.priv));
  const r = await call("POST", `/api/spaces/${spaceId}/rotate-epoch`, {
    epoch: 1, admin_x_pub: creatorX.pub, keys: [], signature: sig,
  });
  check("rotate-epoch valid advance", r.status === 200, JSON.stringify(r.data));
  const m = await call("GET", `/api/spaces/${spaceId}/members`);
  check("rotate-epoch bumped epoch", m.data && m.data.epoch === 1);
}
{
  const sig = b64url(ed25519.sign(epochInput(spaceId, 1), control.priv));
  const r = await call("POST", `/api/spaces/${spaceId}/rotate-epoch`, {
    epoch: 1, admin_x_pub: creatorX.pub, keys: [], signature: sig,
  });
  check("rotate-epoch stale rejected", r.status === 400, JSON.stringify(r.data));
}
{
  const sig = b64url(ed25519.sign(epochInput(spaceId, 2), control.priv));
  const r = await call("POST", `/api/spaces/${spaceId}/rotate-epoch`, {
    epoch: 2, admin_x_pub: creatorX.pub,
    keys: [{ pubkey: keypair().pub, wrapped: "J".repeat(44) }],
    signature: sig,
  });
  check("rotate-epoch non-member key rejected", r.status === 400, JSON.stringify(r.data));
}

// 9. regression: kick still works (route change did not break it).
{
  const sig = b64url(ed25519.sign(kickInput(spaceId, member.pub, 2), control.priv));
  const epochSig = b64url(ed25519.sign(epochInput(spaceId, 2), control.priv));
  const r = await call("POST", `/api/spaces/${spaceId}/kick`, {
    pubkey: member.pub, epoch: 2, signature: sig,
    keys: [], admin_x_pub: creatorX.pub, epoch_signature: epochSig,
  });
  check("kick regression", r.status === 200, JSON.stringify(r.data));
}

const failed = results.filter(([, ok]) => !ok).length;
console.log(`${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
