/* Muse Relay HTTP client + high-level flows (browser).
 * The server is a dumb pipe: it never sees keys, code words, or plaintext.
 */
import {
  b64urlEncode, b64urlDecode, randomBytes,
  genCodeWords, deriveLookup, deriveKek,
  wrapSpaceKey, unwrapSpaceKey,
  encryptMessage, decryptMessage,
  genMemberKeypair, signMessage, verifyMessage,
  genXKeypair, signMessageV2, verifyMessageV2,
  genControlKeypair, wrapControlSeed, unwrapControlSeed, controlPubFromSeed,
  signMemberCert, verifyMemberCert,
  parseRelayLink,
} from "./crypto.js";

export * from "./crypto.js";

async function req(base, path, opts = {}) {
  const res = await fetch(base + path, {
    ...opts,
    headers: { "content-type": "application/json", ...(opts.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data;
}

/** Create a space. Everything secret is generated on this device; the server
 *  only receives the lookup fingerprint, the wrapped key blob (which it
 *  cannot open), the control public key, and our certificate-signed member
 *  entry. */
export async function createSpace(base, displayName) {
  const spaceId = b64urlEncode(randomBytes(16)); // 22 chars
  const spaceKey = randomBytes(32);
  const codeWords = genCodeWords(8);
  const lookup = await deriveLookup(codeWords);
  const kek = await deriveKek(codeWords, lookup);
  const wrapped = await wrapSpaceKey(kek, spaceKey);
  const control = genControlKeypair();
  const wrappedControl = await wrapControlSeed(spaceKey, control.seedB64);
  const member = genMemberKeypair();
  // Rotation capability from birth: the creator's X25519 key doubles as
  // the admin wrapping key (see relay.py create).
  const xkey = genXKeypair();
  const cert = signMemberCert(control.seedB64, spaceId, member.pubB64, displayName);
  await req(base, "/api/spaces", {
    method: "POST",
    body: JSON.stringify({
      space_id: spaceId,
      lookup,
      wrapped,
      wrapped_control: wrappedControl,
      control_pub: control.pubB64,
      display_name: displayName,
      pubkey: member.pubB64,
      cert,
      x_pubkey: xkey.pubB64,
    }),
  });
  return {
    spaceId,
    keyB64: b64urlEncode(spaceKey),
    code: codeWords.join(" "),
    member: { ...member, xPubB64: xkey.pubB64, xPrivB64: xkey.privB64 },
    controlPubB64: control.pubB64,
    link: `${base}/s/${spaceId}#k=${b64urlEncode(spaceKey)}`,
  };
}

/** Register this device's member keypair. Needs the control seed, which only
 *  space-key holders can unwrap. */
async function registerMember(base, spaceId, controlSeedB64, displayName) {
  const member = genMemberKeypair();
  const xkey = genXKeypair();
  const cert = signMemberCert(controlSeedB64, spaceId, member.pubB64, displayName);
  const mres = await req(base, `/api/spaces/${spaceId}/members`, {
    method: "POST",
    body: JSON.stringify({ display_name: displayName, pubkey: member.pubB64, cert, x_pubkey: xkey.pubB64 }),
  });
  return { member: { ...member, xPubB64: xkey.pubB64, xPrivB64: xkey.privB64 }, members: mres.members };
}

/** Look up a space from the 8-word pairing code WITHOUT registering.
 *  Code words never leave the device: only their SHA-256 fingerprint goes
 *  over the wire. Lets callers validate the space before registering. */
export async function codeLookup(base, codeWords) {
  const words = codeWords.trim().toLowerCase().split(/\s+/);
  if (words.length !== 8) throw new Error("code must be 8 words");
  const lookup = await deriveLookup(words);
  const data = await req(base, "/api/spaces/join", {
    method: "POST",
    body: JSON.stringify({ lookup }),
  });
  const kek = await deriveKek(words, lookup);
  const spaceKey = await unwrapSpaceKey(kek, data.wrapped);
  const controlSeed = await unwrapControlSeed(spaceKey, data.wrapped_control);
  // Pin the control key: derive it from the seed ourselves and refuse to
  // proceed if the server's claimed control_pub differs.
  const controlPub = controlPubFromSeed(controlSeed);
  if (data.control_pub !== controlPub)
    throw new Error("control key mismatch: the server's control key does not match this space");
  return {
    spaceId: data.space_id,
    keyB64: b64urlEncode(spaceKey),
    controlSeedB64: controlSeed,
    controlPubB64: controlPub,
    code: words.join(" "),
  };
}

/** Register this device's member keypair using an already-unwrapped control
 *  seed (from codeLookup or a link key). */
export async function registerWithSeed(base, spaceId, controlSeedB64, displayName) {
  const { member, members } = await registerMember(
    base, spaceId, controlSeedB64, displayName);
  return { member, members };
}

/** Join with the 8-word pairing code. Code words never leave the device:
 *  only their SHA-256 fingerprint goes over the wire. */
export async function joinWithCode(base, codeWords, displayName) {
  const lk = await codeLookup(base, codeWords);
  const { member, members } = await registerWithSeed(
    base, lk.spaceId, lk.controlSeedB64, displayName);
  return {
    spaceId: lk.spaceId,
    keyB64: lk.keyB64,
    code: lk.code,
    member,
    members,
    controlPubB64: lk.controlPubB64,
    link: `${base}/s/${lk.spaceId}#k=${lk.keyB64}`,
  };
}

/** Join with a key carried in the URL fragment (browsers never send it). */
export async function joinWithKey(base, spaceId, keyB64, displayName) {
  const spaceKey = b64urlDecode(keyB64);
  if (spaceKey.length !== 32) throw new Error("bad key in link");
  const ctrl = await req(base, `/api/spaces/${spaceId}/control`);
  const controlSeed = await unwrapControlSeed(spaceKey, ctrl.wrapped_control);
  const controlPub = controlPubFromSeed(controlSeed);
  if (ctrl.control_pub !== controlPub)
    throw new Error("control key mismatch: the server's control key does not match this space");
  const { member, members } = await registerMember(
    base, spaceId, controlSeed, displayName);
  return {
    spaceId,
    keyB64,
    member,
    members,
    controlPubB64: controlPub,
    link: `${base}/s/${spaceId}#k=${keyB64}`,
  };
}

/** Join with a full relay link. The key comes from the URL fragment, which
 *  browsers never send to servers. */
export async function joinWithLink(linkUrl, displayName) {
  const parsed = parseRelayLink(linkUrl);
  if (!parsed) throw new Error("that doesn't look like a Muse Relay link");
  const u = new URL(linkUrl);
  return joinWithKey(u.origin, parsed.spaceId, parsed.keyB64, displayName);
}

/** Verify every roster certificate against the control public key. Entries
 *  that fail are flagged and must not be trusted. */
export function verifyRoster(spaceId, controlPubB64, members) {
  return members.map((m) => ({
    ...m,
    certOk: verifyMemberCert(controlPubB64, spaceId, m.pubkey,
      m.display_name, m.cert),
  }));
}

export async function sendMessage(base, spaceId, keyB64, member, author, body) {
  const { nonce, ciphertext } = await encryptMessage(
    b64urlDecode(keyB64), author, body);
  const signature = signMessage(member.privB64, spaceId, nonce, ciphertext);
  // Client-generated message id: the server dedupes on it, so a retried
  // POST (lost response) never double-posts.
  const rand = Math.floor(Math.random() * 46656).toString(36).padStart(3, "0");
  const id = `${String(Date.now()).padStart(15, "0")}-${rand}`;
  return req(base, `/api/spaces/${spaceId}/messages`, {
    method: "POST",
    body: JSON.stringify({
      id, ciphertext, nonce, pubkey: member.pubB64, signature,
    }),
  });
}

/** Roster-bound display name. names is a Map of pubkey -> {name, certOk}.
 * Mirrors relay.py resolve_author: the plaintext author field inside the
 * envelope is SELF-ASSERTED and is never displayed when a verified roster
 * entry exists for the signing key; it is only a clearly-marked fallback. */
export function resolveAuthor(pubkey, names, plaintextAuthor) {
  const entry = names ? names.get(pubkey) : null;
  if (entry && entry.certOk) return { display: entry.name, verified: true };
  if (plaintextAuthor)
    return { display: `[unverified name] ${plaintextAuthor}`, verified: false };
  return { display: "[unverified name]", verified: false };
}

/** Fetch + decrypt + verify. Messages that fail verification or decryption
 *  are returned with flags rather than dropped, so problems stay visible.
 *  Version-aware: v2 messages are verified under the v2 domain, and this
 *  client — which holds only the long-lived space key — cannot decrypt
 *  them. That is reported distinctly in the UI, never rendered as if it
 *  were plaintext. */
export async function fetchMessages(base, spaceId, keyB64, since = "", limit = 50) {
  const data = await req(base,
    `/api/spaces/${spaceId}/messages?since=${encodeURIComponent(since)}&limit=${limit}`);
  const out = [];
  for (const m of data.messages) {
    const version = m.version === 2 ? 2 : 1;
    const sigOk = version === 2
      ? verifyMessageV2(m.pubkey, spaceId, m.epoch, m.nonce, m.ciphertext, m.signature)
      : verifyMessage(m.pubkey, spaceId, m.nonce, m.ciphertext, m.signature);
    let plaintext = null, decryptOk = true;
    if (version === 2) {
      // Epoch-key ciphertext: undecryptable with the space key alone.
      decryptOk = false;
    } else {
      try {
        plaintext = await decryptMessage(b64urlDecode(keyB64), m.nonce, m.ciphertext);
      } catch {
        decryptOk = false;
      }
    }
    out.push({ ...m, version, sigOk, decryptOk, plaintext });
  }
  return out;
}

export async function deleteSpace(base, spaceId, codeWords) {
  const words = codeWords.trim().toLowerCase().split(/\s+/);
  const lookup = await deriveLookup(words);
  return req(base, `/api/spaces/${spaceId}`, {
    method: "DELETE",
    body: JSON.stringify({ lookup }),
  });
}

/* Prompt a friend copies to their AI agent from the space landing page.
 * It embeds the full invitation link (the page knows location.href,
 * fragment included) or, for a code-word join, the 8 words — the visitor
 * explicitly chose to share them by bringing them to this page. It points
 * the agent at {origin}/llms.txt for the full protocol, and lays down the
 * standing rules: the key/code stays secret and never goes in a sent
 * message; check for new messages every 30 minutes; trust only verified
 * signatures. */
export function agentSetupPrompt({ link, code, origin }) {
  const secret = link
    ? `My invitation link (private — the part after #k= is the encryption key; keep it secret and never put the link or the key in any message you send):\n${link}`
    : `My 8-word pairing code (private — keep it secret and never put it in any message you send):\n${code}`;
  const join = link
    ? `join the space through the link above.`
    : `join the space at ${origin}/s using these code words.`;
  return `I've been invited to an encrypted Muse Relay space. Join it for me and keep an eye on it for new messages.\n\n${secret}\n\nFirst read ${origin}/llms.txt and follow it, then ${join} Check the space for new messages every 30 minutes and tell me about anything new — only trust messages whose signatures verify.`;
}

/* Clipboard write with a fallback for browsers/contexts where the
 * async clipboard API is unavailable. */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch { /* fall through to the legacy path */ }
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  ta.remove();
}
