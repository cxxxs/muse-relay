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
   an X25519 keypair; the control seed is distributed to every joiner
   (wrapped with the space key), and each joiner self-signs their own
   member certificate with the unwrapped seed — so admission control is
   link secrecy, not creator-only signing (see Honest limitations).
   Every member created by a rotation-capable client
   registers an `x_pubkey` at join.
2. A control-seed holder kicks a member (`relay.py kick <space-id> <pubkey>`):
   the server removes the member, advances the epoch by 1, and stores
   the fresh wrapped epoch keys — all in ONE write (atomic kick).
   If a kick's response is lost, the kicker's pending epoch key
   survives locally and `relay.py republish <space-id>` re-uploads the
   bundle for the current epoch.
3. The kicker wraps the fresh 256-bit epoch key per REMAINING member:
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
- **Admission control is link secrecy, not creator-only privilege.**
  Because the control seed is distributed to every joiner (wrapped with
  the space key) and each joiner self-signs their own member certificate
  with the unwrapped seed, every seed holder has admin rights in
  practice (issue member certificates, kick, rotate). "Creator-only"
  kick/rotate currently holds for honest clients only.
- **Rotation is forward-only, including v1 history.** As a design rule,
  old keys retained in key history still decrypt old messages, the same
  as kick (a kicked member keeps reading pre-kick messages). Rotation
  blocks future joins / future messages only; it does not evict existing
  members (that is kick) and does not protect already-distributed history.
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

## Improvements batch (items 2, 7, 1, 4, 5, 6)

Built in that order after the Phase 1 audit. Item 3 (creator-approval
joins) is deliberately NOT implemented: it would require removing
wrapped_control distribution and adding an approval flow, which is a
model change (open group → approval group), not a patch.

- **Item 2 — pubkey fingerprints in display.** Every member display
  carries the first 6 characters of their base64url pubkey
  (`jojo · a3f9x2`), in the relay.py CLI (`members`, `fetch`) and the
  web UI (roster + messages). Names are self-asserted and not unique;
  the fingerprint is what tells duplicates apart. It is a display
  disambiguator, not a security identifier — pinning must use the full
  pubkey. The server additionally rejects duplicate display names on
  join (409), but that check is advisory only: it races under KV
  eventual consistency, so the fingerprint display is the real defense.
- **Item 7 — roster anti-rollback.** The client persists `(epoch,
  roster_hash)` history in the encrypted local space state and, on
  every roster read (`members`, hence `fetch` and polls), warns when
  the epoch decreases, when a member disappears without an epoch
  increase (a legitimate kick always bumps the epoch), or when the
  roster hash reverts to a previously seen state at an epoch at or
  below the previous roster's epoch. ANY roster change produces a
  notice as generic client behavior, recorded in the audit log.
  Limits: a brand-new joiner has no history and cannot detect a
  rollback; and the server cannot re-admit a kicked member into the
  current epoch by itself (it lacks epoch-key plaintext) — what history
  checking catches is a server showing stale state to a client that
  has already seen newer state.
- **Item 1 — second-channel control-pubkey pinning.** `join-link` and
  `join-code` accept `--expect-control-fp` (full base64url control
  pubkey or its short fingerprint); a mismatch aborts the join. The
  fingerprint MUST arrive via a second channel — in-band with the link
  it adds nothing. Its precise value is binding the link to the
  expected creator's space (this link = their space, not another space
  on the same hostname), NOT preventing server forgery: for an
  honestly-created space the server cannot forge control keys anyway
  (see `control_pub_from_seed`).
- **Item 4 — link-key rotation.** `relay.py rotate-key` (server endpoint
  `POST /api/spaces/{id}/rotate-key`, authorized by a control-key
  signature over both new wrapped blobs) replaces the space key: the
  old link can no longer join, and the code path rotates with it (the
  code-path blob is re-wrapped under the new key). The client retains
  old keys in key history so old v1 messages stay decryptable.
  Forward-only: rotation does not evict existing members (that is
  kick) and does not protect already-distributed v1 history. In an
  epoch-0 (v1) space, rotation fragments v1 messaging until the space
  moves to v2 — the command warns about this.
- **Item 5 — aggressive rotation.** (a) `relay.py rotate-epoch` advances
  the epoch key WITHOUT removing anyone (server endpoint `POST
  /api/spaces/{id}/rotate-epoch`, epoch must be exactly current + 1,
  bundle rules mirror kick's); this is the command the weekly-rotation
  cron calls. (b) `tools/rotate-on-join.py` is a creator-side opt-in
  hook: when a roster poll reports a newly joined CERTIFIED member, it
  advances the epoch; it is not scheduled by this build. (c) v1 is
  flagged explicitly in display (`[v1]` in the CLI, a v1 badge in the
  web UI). (d) v1 retirement: the server rejects new members without
  an X25519 key, at creation and at join. Pre-existing v1 members and
  v1 messages still work; no NEW member may join without rotation
  capability.
- **Item 6 — keychain local-key storage.** The local at-rest key
  (`MUSE_RELAY_KEY_BACKEND`, default `auto`) is read from the OS
  keychain first (macOS Keychain via `security`, Linux Secret Service
  via `secret-tool`) and falls back to the historical 0400 file with a
  one-time-per-process warning when the keychain is locked or
  unavailable. The unattended poll path must keep working, so a locked
  keychain never blocks and never prompts (10s timeout; a hung or
  missing tool is tried once per process). The macOS path is
  code-review only — it cannot be live-tested on a Linux VM — and on a
  headless Linux box Secret Service is usually absent, so the file
  fallback is the normal path there.
