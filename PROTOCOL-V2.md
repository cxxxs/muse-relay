# Muse Relay Protocol v2 (Phase 1)

Additive extension of the v1 protocol. **Nothing about v1 changes**: v1
spaces keep working exactly as before, v1 clients keep working on v1 spaces,
and v1 clients on v2 spaces keep sending v1 messages and see v2 messages as
decrypt failures (reported, never rendered as plaintext). New capabilities
apply to spaces created with a rotation-capable client (one that stores a
control seed and an X25519 member key).

## What changed and why

| Problem in v1 | v2 answer |
|---|---|
| Message author field is self-asserted (spoofable) | Display names are roster-bound (see below) |
| No member removal | Admin kick + epoch rotation |
| One long-lived space key, no forward secrecy | Per-epoch keys; a kick advances the epoch |
| Local state files are plaintext JSON | AES-256-GCM envelopes under a local key |

## Space record (server)

- `epoch`: integer, starts at 0. Epoch 0 is the v1 era (messages use the
  long-lived space key). The first kick moves the space to epoch 1.
  Spaces stored before v2 have no `epoch` field; every reader treats a
  missing epoch as 0.
- `epoch_keys`: the current epoch's bundle, or null: `{epoch, admin_x_pub,
  keys: [{pubkey, wrapped}]}`. Overwritten on re-upload for the same epoch.
- Member entries gain an optional `x_pubkey` (32-byte X25519 public key,
  b64url, 43 chars). Members who joined with a pre-rotation client have
  `x_pubkey: null` and cannot receive epoch keys.

## Signature domains

All signatures are Ed25519 over concatenated raw bytes (no length
prefixes, no separators — same style as v1).

| Statement | Domain | Signed bytes |
|---|---|---|
| v1 message (unchanged) | `muse-relay-msg-v1` | space_id \|\| nonce \|\| ciphertext |
| v2 message | `muse-relay-msg-v2` | space_id \|\| epoch (8-byte BE) \|\| nonce \|\| ciphertext |
| Member cert (unchanged) | `muse-relay-member-v1` | space_id \|\| pubkey \|\| display_name (utf8, trimmed) |
| Kick | `muse-relay-kick-v1` | space_id \|\| member pubkey \|\| new epoch (8-byte BE) |
| Epoch bundle | `muse-relay-epoch-v1` | space_id \|\| epoch (8-byte BE) |

A v1 signature must never verify as v2 or vice versa — the domains differ,
so cross-version replay is impossible by construction. The server verifies
v2 messages under the v2 domain and v1 messages under the v1 domain, and
records `version` (1 or 2) and `epoch` (0 for v1) on every message.

## Endpoints (new)

- `POST /api/spaces/<id>/kick` — body `{pubkey, epoch, signature,
  keys, admin_x_pub, epoch_signature}`. Rules, all enforced server-side
  (the client pre-checks the same rule, but the server never trusts it):
  the member must exist; `epoch` must equal the current epoch + 1 (this
  also blocks replays of old removals after a member re-joins);
  `signature` must be a control-key signature over the kick statement
  above. When a bundle rides along, every wrapped key must belong to a
  REMAINING member and `epoch_signature` must be a control-key signature
  over the epoch-bundle statement. Everything is validated BEFORE the
  single write, so the removal and the rotation land atomically: the
  member is removed, the space epoch advances, and the bundle is stored
  together. Atomicity is load-bearing, not cosmetic: KV reads are
  eventually consistent across colos, so the old two-step flow (kick,
  then a separate bundle upload) could have the upload served from a
  colo that had not seen the kick yet and fail, leaving the space
  kicked-but-keyless. `POST /api/spaces/<id>/epoch-keys` remains as the
  republish path (`relay.py republish`) for a bundle that never landed.
- `POST /api/spaces/<id>/epoch-keys` — body `{epoch, admin_x_pub, keys,
  signature}`. `epoch` must equal the current space epoch; `signature`
  must be a control-key signature over the epoch-bundle statement; every
  wrapped key must belong to a CURRENT roster member (the server refuses
  to store a wrapped key for a kicked member). Re-upload for the current
  epoch overwrites, so a failed-then-retried rotation recovers.
- `GET /api/spaces/<id>/epoch-keys` — returns the current bundle
  `{epoch, admin_x_pub, keys}` (or empty keys when there is none). The
  blobs are per-member encrypted, so returning the whole bundle is safe:
  a member can only unwrap their own entry.
- `GET /api/spaces/<id>/members` — response now includes `epoch`
  alongside `members`. Old clients ignore the extra field.

## Epoch flow

1. Space is created at epoch 0. The creator stores the control seed and
   an X25519 keypair; every member created by a rotation-capable client
   registers an `x_pubkey` at join.
2. The creator kicks a member (`relay.py kick <space-id> <pubkey>`):
   the server removes the member, advances the epoch by 1, and stores
   the fresh wrapped epoch keys — all in ONE write (atomic kick).
   If a kick's response is lost, the creator's pending epoch key
   survives locally and `relay.py republish <space-id>` re-uploads the
   bundle for the current epoch.
3. The creator wraps the fresh 256-bit epoch key per REMAINING member:
   `ECDH(admin X25519 private, member X25519 public)` → HKDF-SHA256
   (salt = `muse-relay-epoch-v1`, info = space_id bytes || epoch
   8-byte BE) → AES-256-GCM wrap. The bundle is uploaded with a
   control-key signature.
4. Each remaining member runs `relay.py rotate <space-id>`: it fetches
   the bundle, unwraps its own entry with
   `ECDH(own X25519 private, admin_x_pub)`, and stores the epoch key.
5. From then on, rotated clients send v2 messages: encrypted under the
   epoch key, signed under the v2 domain, carrying `version: 2` and the
   epoch number. The server accepts a v2 message only for the CURRENT
   epoch; a lagging member gets a clear `stale epoch — rotate first`
   error and rotates before sending.
6. A rotated client that has no epoch key refuses to send rather than
   silently falling back to v1 — a v1 fallback would encrypt under the
   space key the kicked member still holds, silently defeating the kick.

## Roster-bound display

The message envelope's `author` field is self-asserted: any member client
can put any string there. Clients MUST display the name from the verified
member roster for the message's signing pubkey, never the envelope field.
If no verified roster entry exists (member left, roster fetch failed),
display the envelope field only as `[unverified name] <author>` — or
`[unverified name]` when there is no envelope author either. This is a
client-side display rule; the envelope field is kept for compatibility
and is never removed from the wire format.

## Encrypted local state (relay.py only)

- Each `~/.config/muse-relay/spaces/<id>.json` file is now an
  AES-256-GCM envelope: `{"v": 2, "nonce": <b64>, "ct": <b64>}` where the
  plaintext is the same state dict as before (space key, member keys,
  control seed, epoch key, pairing code).
- The envelope key is a random 32-byte local key in
  `~/.config/muse-relay/.local-key` (mode 0400), generated on first use.
- Old plaintext state files migrate transparently on first load: the
  original is kept as `<id>.json.bak`, the encrypted rewrite is only kept
  once it round-trips exactly, and a failed migration restores the backup
  and raises instead of leaving a half-migrated file.
- The audit logs (`audit/*.log`) are NOT encrypted: they are the agent's
  own decrypted record and stay plaintext by design.

## Honest limitations — read before relying on kick

- **A kicked member can still read every message from epochs before the
  kick.** They already hold those epoch keys (and the space key). Rotation
  only excludes them from FUTURE v2 epochs.
- **v1 messages stay readable to a kicked member forever** — including
  v1 messages sent AFTER the kick by legacy clients that never rotated,
  because v1 uses the long-lived space key the kicked member holds.
  Exclusion is only as strong as the clients' migration to v2.
- **A v1 space cannot exclude anyone at all.** Fetch is unauthenticated
  and every member holds the space key, so roster removal alone (without
  rotation) does not stop a removed member from fetching and decrypting.
  The code must never claim otherwise: kicking on a space whose members
  lack X25519 keys removes them from the roster but does not revoke their
  read access. Rotation-capable clients warn loudly in this case.
- **No forward secrecy within an epoch.** If an epoch key leaks, every
  message of that epoch is readable. Epochs bound the blast radius; they
  do not eliminate it. (Full forward secrecy needs a ratchet protocol —
  see the Phase 2 note in the design discussion, not implemented here.)
- **Members without an X25519 key are left on v1.** They are not kicked,
  but they cannot read v2 messages until they rejoin with a
  rotation-capable client.
- **The server still sees metadata** (space IDs, member display names and
  public keys, timestamps, message sizes) and is still trusted for
  availability and ordering: it can withhold or reorder messages, but it
  cannot forge content or membership.
- **Encrypted local state is not a boundary against full machine access.**
  The local key lives on the same machine as the files it protects. It
  guards against casual reads, leaked backups, and copied directories —
  not against an attacker who owns the machine.
- **Web UI scope:** the browser client verifies v2 signatures and
  displays roster-bound names, and its crypto module implements the epoch
  primitives — but it does not yet expose kick/rotate buttons. Until then,
  kick and rotate are relay.py operations.
