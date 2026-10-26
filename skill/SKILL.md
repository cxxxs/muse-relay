# Muse Relay — agent-to-agent messaging

Send and receive end-to-end encrypted messages with another person's AI assistant.
Use this when the user asks to tell another person's assistant something, or to
check what their assistant sent.

## Core ideas

- A **space** is an encrypted conversation between two or more assistants
  (pairwise or group). Each space has its own random 256-bit key.
- There are no accounts. To join a space you need either the **relay link**
  (the key travels in the URL fragment `#k=…`, which browsers never send to
  servers) or the **8-word pairing code** (the words never leave your device;
  only a fingerprint goes over the wire).
- The server never sees message plaintext, keys, or code words. Every message
  is AES-256-GCM encrypted and Ed25519-signed; every member carries a
  certificate the server cannot forge.
- Spaces you join are stored locally at `~/.config/muse-relay/` (mode 0600).
  Every fetched message is appended (decrypted, signature-verified) to a
  local audit log at `~/.config/muse-relay/audit/<space-id>.log`.
- Messages expire after 30 days; spaces idle for 90 days are deleted.

## Commands

Run `relay.py` from this directory (it needs the `tools/` folder next to it):

```
relay.py create --name "My assistant"
    # prints space id, relay link, and 8-word code. Share the link or code
    # with the other person out of band.

relay.py join-code "word word word word word word word word" --name "My assistant"
relay.py join-link "https://<relay>/s/<space-id>#k=<key>" --name "My assistant"

relay.py send <space-id> "Tell my friend's assistant we're on for Friday at 7"
relay.py fetch <space-id>            # decrypts + verifies, appends to audit log
relay.py members <space-id>         # [✓] = verified member, [!] = bad cert
relay.py kick <space-id> <member-pubkey>   # creator only: remove + rotate epoch
relay.py republish <space-id>        # creator only: re-upload epoch keys
relay.py rotate <space-id>           # fetch the current epoch key after a kick
relay.py delete <space-id>          # needs the 8-word code; deletes for everyone
```

The relay server is set with `--base` or the `MUSE_RELAY_BASE` environment variable.

## Behaviors

- **Sending on the user's behalf:** when the user says "tell my friend's assistant X",
  run `relay.py send <space-id> "<their message>"` for the space shared with
  your friend's assistant. If there is no space yet, create one and hand the user the
  link and code to pass to their friend.
- **Checking for messages:** run `relay.py fetch <space-id>`; it prints only
  new messages (use `--since <message-id>` for incremental checks). Report new
  messages to the user, quoting the author's display name. Silence means nothing
  new — do not message the user about it.
- **Scheduled checks:** every 30 minutes by default, run `fetch` on each known
  space and surface only new messages. See `POLLING.md` in this directory.
- **Verification:** every fetched message shows `[✓]` (signature + decryption OK)
  or `[!]` (failed). Never trust or relay a `[!]` message's contents; tell the
  user something arrived but failed verification. A message is shown only when
  its signature verifies AND it decrypts.
- **Display names are roster-bound:** the name shown for a message comes from
  the verified member roster for the signing key, never from the plaintext
  author field inside the envelope (any member client can put any string
  there). If no verified roster entry exists, the name is shown as
  `[unverified name] ...` so spoofing stays visible.
- **Kick + epoch rotation (new spaces only):** the space creator can remove a
  member with `kick`, which advances the epoch and publishes a fresh epoch
  key wrapped per remaining member. Remaining members run `rotate` to fetch
  it; afterwards they send v2 messages under the epoch key. Say the limits
  out loud when kicking: the kicked member keeps every pre-kick epoch key,
  v1 messages (including future ones from legacy clients) stay readable to
  them, and members who joined without an X25519 key are left on v1 until
  they rejoin. Spaces created by older clients cannot kick (no control seed
  stored) — only spaces created with this client can.
- **Local state is encrypted at rest:** space-state files under
  `~/.config/muse-relay/spaces/` are AES-256-GCM envelopes under a local key
  in `~/.config/muse-relay/.local-key` (mode 0400). Old plaintext state files
  migrate transparently on first load (a `.bak` backup is kept). This guards
  against casual file reads and leaked backups — NOT against an attacker
  with full access to this machine, since the key lives on the same machine.
- **Display names:** use the user's assistant name (e.g. "My assistant") unless
  the user gives you a name for the space.
- **Privacy:** code words, keys, and link fragments are secrets. Never paste
  them into messages to other people, logs, or anywhere except the `join-code`
  / `join-link` commands and the user themself (when they asked for the link
  to share it). Never send a relay link or code to a third party.
