#!/usr/bin/env python3
"""Muse Relay agent helper.

End-to-end encrypted messaging between AI agents. The server is a dumb
pipe: it never sees keys, code words, or message plaintext.

Usage:
    relay.py create --name "My assistant"
    relay.py join-code "maple otter ... grove" --name "My assistant"
    relay.py join-link "https://.../s/<id>#k=<key>" --name "My assistant"
    relay.py send <space-id> "Tell my friend's assistant we're on for Friday"
    relay.py fetch <space-id>            # decrypt + verify, append to audit log
    relay.py members <space-id>
    relay.py kick <space-id> <member-pubkey>   # seed holder: remove + rotate
    relay.py republish <space-id>        # seed holder: re-upload epoch keys
    relay.py rotate <space-id>           # fetch the current epoch key
    relay.py rotate-key <space-id>      # seed holder + code: rotate link key
    relay.py rotate-epoch <space-id>    # seed holder: advance epoch, no removal
    relay.py delete <space-id>           # needs the 8-word code

Set the relay server with --base or the MUSE_RELAY_BASE environment variable.

Keys and code words are stored in ~/.config/muse-relay/ with mode 0600.
Every fetched message is appended (decrypted) to a local audit log:
    ~/.config/muse-relay/audit/<space-id>.log   (JSON lines)
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
from words import WORDS  # noqa: E402

DEFAULT_BASE = os.environ.get("MUSE_RELAY_BASE", "")
CONFIG_DIR = os.path.expanduser("~/.config/muse-relay")
SPACES_DIR = os.path.join(CONFIG_DIR, "spaces")
AUDIT_DIR = os.path.join(CONFIG_DIR, "audit")
SIGN_CTX = b"muse-relay-msg-v1"


def _sig_input(space_id: str, nonce_b64: str, ct_b64: str) -> bytes:
    # Must match client/crypto.js sigInput and the worker exactly:
    # domain || raw space-id bytes || raw nonce || raw ciphertext.
    return (SIGN_CTX + b64d(space_id) + b64d(nonce_b64) + b64d(ct_b64))


CERT_CTX = b"muse-relay-member-v1"


def _cert_input(space_id: str, pub_b64: str, display_name: str) -> bytes:
    # Must match client/crypto.js memberCertInput and the worker exactly.
    return (CERT_CTX + b64d(space_id) + b64d(pub_b64)
            + display_name.strip().encode())


def gen_control_keypair():
    seed = secrets.token_bytes(32)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return b64e(seed), b64e(pub.public_bytes_raw())


def control_pub_from_seed(seed_b64: str) -> str:
    """Derive the Ed25519 control public key from a control seed.

    This is the pinning primitive: a client that unwraps the control seed
    can compute the control public key itself and must never trust a
    server-supplied control_pub that differs from it. A server that swaps
    in a different control_pub (for which it holds the seed) could mint
    rogue member certificates that a trusting client would accept."""
    pub = Ed25519PrivateKey.from_private_bytes(b64d(seed_b64)).public_key()
    return b64e(pub.public_bytes_raw())


def wrap_control_seed(key: bytes, seed_b64: str) -> str:
    pt = json.dumps({"v": 1, "kind": "control-seed", "seed": seed_b64}).encode()
    nonce = secrets.token_bytes(12)
    return b64e(nonce + AESGCM(key).encrypt(nonce, pt, None))


def unwrap_control_seed(key: bytes, wrapped_b64: str) -> str:
    blob = b64d(wrapped_b64)
    m = json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], None))
    if m.get("v") != 1 or m.get("kind") != "control-seed" \
            or not isinstance(m.get("seed"), str):
        raise ValueError("bad control seed")
    return m["seed"]


def sign_member_cert(seed_b64: str, space_id: str, pub_b64: str,
                     display_name: str) -> str:
    seed = Ed25519PrivateKey.from_private_bytes(b64d(seed_b64))
    return b64e(seed.sign(_cert_input(space_id, pub_b64, display_name)))


def verify_member_cert(control_pub_b64: str, space_id: str, pub_b64: str,
                       display_name: str, cert_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64d(control_pub_b64))
        pub.verify(b64d(cert_b64), _cert_input(space_id, pub_b64, display_name))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- v2: epochs
# Phase 1 adds admin kick + epoch key rotation on top of the v1 protocol.
# Everything here is additive: v1 spaces (and v1 clients) keep working
# exactly as before. Rotation only ever applies to spaces created with a
# client that stores a control seed and an X25519 member key (see create).

# v2 message signatures bind the epoch, so a ciphertext cannot be replayed
# into a different epoch.
MSG2_CTX = b"muse-relay-msg-v2"
# Admin signatures: control-key signatures over a kick / epoch-bundle
# statement. The server verifies these against the stored control_pub, so
# only the creator (holder of the control seed) can kick or rotate.
KICK_CTX = b"muse-relay-kick-v1"
EPOCH_CTX = b"muse-relay-epoch-v1"
# HKDF salt for epoch-key wrapping. Using the domain string as the salt
# keeps an epoch wrapping key from ever colliding with another derived key.
EPOCH_WRAP_SALT = b"muse-relay-epoch-v1"


def epoch_bytes(epoch: int) -> bytes:
    if not isinstance(epoch, int) or epoch < 0 or epoch > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("epoch out of range")
    return epoch.to_bytes(8, "big")


def _kick_input(space_id: str, pub_b64: str, epoch: int) -> bytes:
    # Must match src/worker.js kickInput and client/crypto.js kickInput:
    # domain || raw space-id bytes || raw member pubkey || epoch (8-byte BE).
    return (KICK_CTX + b64d(space_id) + b64d(pub_b64) + epoch_bytes(epoch))


def _epoch_input(space_id: str, epoch: int) -> bytes:
    # Must match src/worker.js epochInput and client/crypto.js epochInput:
    # domain || raw space-id bytes || epoch (8-byte BE).
    return (EPOCH_CTX + b64d(space_id) + epoch_bytes(epoch))


def _sig2_input(space_id: str, epoch: int, nonce_b64: str, ct_b64: str) -> bytes:
    # Must match src/worker.js sig2Input and client/crypto.js sig2Input:
    # domain || raw space-id bytes || epoch (8-byte BE) || raw nonce ||
    # raw ciphertext.
    return (MSG2_CTX + b64d(space_id) + epoch_bytes(epoch)
            + b64d(nonce_b64) + b64d(ct_b64))


def sign_kick(seed_b64: str, space_id: str, pub_b64: str, epoch: int) -> str:
    seed = Ed25519PrivateKey.from_private_bytes(b64d(seed_b64))
    return b64e(seed.sign(_kick_input(space_id, pub_b64, epoch)))


def verify_kick(control_pub_b64: str, space_id: str, pub_b64: str,
                epoch: int, sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64d(control_pub_b64))
        pub.verify(b64d(sig_b64), _kick_input(space_id, pub_b64, epoch))
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_epoch_bundle(seed_b64: str, space_id: str, epoch: int) -> str:
    seed = Ed25519PrivateKey.from_private_bytes(b64d(seed_b64))
    return b64e(seed.sign(_epoch_input(space_id, epoch)))


def verify_epoch_bundle(control_pub_b64: str, space_id: str, epoch: int,
                        sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64d(control_pub_b64))
        pub.verify(b64d(sig_b64), _epoch_input(space_id, epoch))
        return True
    except (InvalidSignature, ValueError):
        return False


# Link-key rotation signatures. The statement binds BOTH new wrapped
# blobs, so a rotation request cannot be repurposed to rotate one blob
# but not the other. Must match src/worker.js rotateKeyInput exactly:
# domain || raw space-id bytes || raw new wrapped_control ||
# raw new wrapped (code-path blob).
ROTATEKEY_CTX = b"muse-relay-rotatekey-v1"


def _rotatekey_input(space_id: str, wrapped_control_b64: str,
                     wrapped_b64: str) -> bytes:
    return (ROTATEKEY_CTX + b64d(space_id) + b64d(wrapped_control_b64)
            + b64d(wrapped_b64))


def sign_rotate_key(seed_b64: str, space_id: str,
                    wrapped_control_b64: str, wrapped_b64: str) -> str:
    seed = Ed25519PrivateKey.from_private_bytes(b64d(seed_b64))
    return b64e(seed.sign(
        _rotatekey_input(space_id, wrapped_control_b64, wrapped_b64)))


def verify_rotate_key(control_pub_b64: str, space_id: str,
                      wrapped_control_b64: str, wrapped_b64: str,
                      sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64d(control_pub_b64))
        pub.verify(b64d(sig_b64),
                   _rotatekey_input(space_id, wrapped_control_b64,
                                    wrapped_b64))
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_message_v2(priv_b64: str, space_id: str, epoch: int,
                    nonce_b64: str, ct_b64: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(b64d(priv_b64))
    return b64e(priv.sign(_sig2_input(space_id, epoch, nonce_b64, ct_b64)))


def verify_message_v2(pub_b64: str, space_id: str, epoch: int,
                      nonce_b64: str, ct_b64: str, sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64d(pub_b64))
        pub.verify(b64d(sig_b64), _sig2_input(space_id, epoch, nonce_b64, ct_b64))
        return True
    except (InvalidSignature, ValueError):
        return False


def validate_kick_request(roster_pubkeys, control_pub_b64: str, space_id: str,
                          current_epoch: int, pub_b64: str, epoch: int,
                          sig_b64: str):
    """The kick authorization rule, shared by the client pre-check and the
    server (which re-checks it independently — never trust the client).
    Raises ValueError on any violation: unknown member, forged signature,
    or an epoch that is not exactly current + 1 (which also blocks replays
    of old removals after a member re-joins)."""
    if pub_b64 not in roster_pubkeys:
        raise ValueError("unknown member")
    if epoch != current_epoch + 1:
        raise ValueError("stale epoch")
    if not verify_kick(control_pub_b64, space_id, pub_b64, epoch, sig_b64):
        raise ValueError("bad kick signature")


def gen_member_x_keypair():
    """A member's X25519 keypair, used only for epoch-key wrapping. It is
    separate from the Ed25519 signing keypair: signing proves who you are,
    ECDH wraps keys to you."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    return b64e(pub_raw), b64e(priv_raw)


def ecdh_shared(priv_b64: str, pub_b64: str) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(b64d(priv_b64))
    pub = X25519PublicKey.from_public_bytes(b64d(pub_b64))
    return priv.exchange(pub)


def epoch_wrapping_key(shared: bytes, space_id: str, epoch: int) -> bytes:
    """Derive the AES-256-GCM key that wraps one member's copy of an epoch
    key. The space id and epoch are bound into the HKDF info, so a wrapped
    blob cannot be transplanted into another space or epoch."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=EPOCH_WRAP_SALT,
                info=b64d(space_id) + epoch_bytes(epoch)).derive(shared)


def wrap_epoch_key(wrapping_key: bytes, epoch_key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(wrapping_key).encrypt(nonce, epoch_key, None)
    return b64e(nonce + ct)


def unwrap_epoch_key(wrapping_key: bytes, wrapped_b64: str) -> bytes:
    blob = b64d(wrapped_b64)
    return AESGCM(wrapping_key).decrypt(blob[:12], blob[12:], None)


def resolve_author(pub_b64: str, roster: dict, plaintext_author):
    """Roster-bound display name for a message.

    roster maps a member pubkey to (display_name, cert_ok). The plaintext
    `author` field inside the message envelope is SELF-ASSERTED — any
    member client can put any string there — so it is NEVER displayed when
    a verified roster entry exists for the signing key. It is only a
    fallback, clearly marked, when the roster has no verified entry (member
    left, roster fetch failed, or a pre-roster message). Returns
    (display_name, verified)."""
    entry = roster.get(pub_b64)
    if entry is not None and entry[1]:
        return entry[0], True
    if plaintext_author:
        return f"[unverified name] {plaintext_author}", False
    return "[unverified name]", False


def check_control_fp(control_pub_b64: str, expect):
    """Second-channel control-key pinning for joins.

    expect may be the full base64url control pubkey or its short
    fingerprint (short_fp). Raises ValueError on mismatch; None means
    'do not pin' (the default: joining trusts the link alone).

    The fingerprint MUST arrive via a second channel — a fingerprint
    pasted in the same message as the link adds nothing, because anyone
    who can swap the link can swap the fingerprint with it. Its value
    is binding the link to the EXPECTED creator's space: confirming
    this link corresponds to their space, not another space on the same
    hostname. It is NOT about preventing server forgery: for an
    honestly-created space the server cannot forge control keys anyway,
    because the client derives control_pub from the seed unwrapped with
    the space key (which the server never sees) and aborts on mismatch
    with the server's claim (see control_pub_from_seed)."""
    if expect is None:
        return
    expect = expect.strip()
    if expect != control_pub_b64 and expect != short_fp(control_pub_b64):
        raise ValueError(
            "control pubkey fingerprint mismatch: the link's control key "
            "does not match the expected fingerprint — the link may point "
            "at a different space than expected; refusing to join")
def short_fp(pub_b64: str) -> str:
    """Stable short fingerprint of a member/control public key: the first
    6 characters of its base64url form. It is a DISPLAY disambiguator,
    not a security identifier: it tells humans apart when two members
    share a display name (names are self-asserted and not unique), but
    pinning must use the full pubkey (or the --expect-control-fp check),
    never the short form alone. The same rule is used by the web UI."""
    return (pub_b64 or "")[:6]


def display_with_fp(display_name: str, pub_b64: str) -> str:
    """Display name with its key fingerprint: 'jojo · a3f9x2'. A duplicate
    name with a different fingerprint is visibly a different member."""
    return f"{display_name} · {short_fp(pub_b64)}"


# ---------------------------------------------------------------- crypto

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def gen_code_words(n: int = 8):
    raw = secrets.token_bytes((n * 11 + 7) // 8)
    val = int.from_bytes(raw, "big")
    return [WORDS[(val >> (11 * i)) & 0x7FF] for i in range(n - 1, -1, -1)]


def derive_lookup(words) -> str:
    # b64url( SHA256("muse-relay-v1:lookup:" + code_words)[0:12] ) — 16 chars.
    h = hashlib.sha256(b"muse-relay-v1:lookup:" + " ".join(words).encode()).digest()
    return b64e(h[:12])


def derive_kek(words, lookup_b64: str) -> bytes:
    # PBKDF2-HMAC-SHA256(pw=code_words, salt="muse-relay-v1:wrap:"+lookup, 600k, 32)
    return hashlib.pbkdf2_hmac(
        "sha256", " ".join(words).encode(),
        b"muse-relay-v1:wrap:" + lookup_b64.encode(), 600_000, 32)


def wrap_space_key(kek: bytes, space_key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ct = AESGCM(kek).encrypt(nonce, space_key, None)
    return b64e(nonce + ct)


def unwrap_space_key(kek: bytes, wrapped_b64: str) -> bytes:
    blob = b64d(wrapped_b64)
    return AESGCM(kek).decrypt(blob[:12], blob[12:], None)


def encrypt_message(key: bytes, author: str, body: str):
    pt = json.dumps(
        {"v": 1, "author": author, "ts": int(time.time() * 1000), "body": body}
    ).encode()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, pt, None)
    return b64e(nonce), b64e(ct)


def decrypt_message(key: bytes, nonce_b64: str, ct_b64: str):
    pt = AESGCM(key).decrypt(b64d(nonce_b64), b64d(ct_b64), None)
    return json.loads(pt.decode())


def _b36(n: int) -> str:
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    for _ in range(3):
        out = chars[n % 36] + out
        n //= 36
    return out


def gen_member_keypair():
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    return b64e(pub_raw), b64e(priv_raw)


def sign_message(priv_b64: str, space_id: str, nonce_b64: str, ct_b64: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(b64d(priv_b64))
    return b64e(priv.sign(_sig_input(space_id, nonce_b64, ct_b64)))


def verify_message(pub_b64: str, space_id: str, nonce_b64: str, ct_b64: str,
                   sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(b64d(pub_b64))
        pub.verify(b64d(sig_b64), _sig_input(space_id, nonce_b64, ct_b64))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- storage

LOCAL_KEY_FILE = os.path.join(CONFIG_DIR, ".local-key")

_KEYCHAIN_SERVICE = "muse-relay"
_KEYCHAIN_ACCOUNT = "local-key"
_KEYCHAIN_WARNED = False
# In-process memoization: a hung or missing keychain tool is tried once
# per process, not once per state operation — a CLI invocation does
# several state reads/writes, and a 10s timeout on each would be absurd.
_KEYCHAIN_DEAD = False
_KEYCHAIN_PUT_OK = False


def _keychain_tool():
    """Return the platform keychain CLI name, or None when no supported
    tool exists. macOS uses `security`, Linux uses `secret-tool`
    (Secret Service). Other platforms have no keychain backend."""
    if sys.platform == "darwin":
        return "security"
    if sys.platform.startswith("linux"):
        return "secret-tool"
    return None


def _keychain_get():
    """Return the stored local key (bytes) or None. Never raises, never
    prompts: a missing tool, a locked keychain, denied access, or a
    timeout all mean 'unavailable' and the caller falls back to the
    file. The key is stored base64-encoded; anything else is rejected.
    A hung/missing tool marks the keychain dead for this process."""
    global _KEYCHAIN_DEAD
    if _keychain_tool() is None or _KEYCHAIN_DEAD:
        return None
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["security", "find-generic-password",
                 "-s", _KEYCHAIN_SERVICE, "-a", _KEYCHAIN_ACCOUNT, "-w"],
                capture_output=True, text=True, timeout=10)
        else:
            out = subprocess.run(
                ["secret-tool", "lookup",
                 _KEYCHAIN_SERVICE, _KEYCHAIN_ACCOUNT],
                capture_output=True, text=True, timeout=10)
        if out.returncode != 0:
            return None
        raw = b64d(out.stdout.strip())
        return raw if len(raw) == 32 else None
    except Exception:
        _KEYCHAIN_DEAD = True
        return None


def _keychain_put(key: bytes) -> bool:
    """Best-effort store of the local key in the keychain. Returns True
    on success, False otherwise (the caller keeps the file). Never
    raises, never prompts: secret-tool reads the secret from stdin, and
    the security invocation is non-interactive with a timeout. A
    successful put is remembered for this process; a hung/missing tool
    marks the keychain dead for this process."""
    global _KEYCHAIN_DEAD, _KEYCHAIN_PUT_OK
    if _keychain_tool() is None or _KEYCHAIN_DEAD or _KEYCHAIN_PUT_OK:
        return _KEYCHAIN_PUT_OK
    encoded = b64e(key)
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["security", "add-generic-password",
                 "-s", _KEYCHAIN_SERVICE, "-a", _KEYCHAIN_ACCOUNT,
                 "-w", encoded, "-U"],
                capture_output=True, text=True, timeout=10)
        else:
            out = subprocess.run(
                ["secret-tool", "store", "--label", "Muse Relay local key",
                 _KEYCHAIN_SERVICE, _KEYCHAIN_ACCOUNT],
                input=encoded, capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            _KEYCHAIN_PUT_OK = True
            return True
        return False
    except Exception:
        _KEYCHAIN_DEAD = True
        return False


def _write_local_key_file(key: bytes):
    tmp = LOCAL_KEY_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key)
    os.chmod(tmp, 0o400)
    os.replace(tmp, LOCAL_KEY_FILE)


def _local_key() -> bytes:
    """The at-rest key for local space-state files (see save_space).

    LIMITATION, stated plainly: this protects state files against casual
    reads — a file copied off the machine, a backup that leaks, a
    directory listing that exposes them — NOT against an attacker with
    full access to this machine, because the key itself lives on the same
    machine. It is defense in depth, not a security boundary. The audit
    logs (audit/*.log) are deliberately NOT covered: they are the agent's
    own decrypted record and stay plaintext.

    Storage backends (MUSE_RELAY_KEY_BACKEND, default "auto"):
    - "auto": the OS keychain first (macOS Keychain via `security`,
      Linux Secret Service via `secret-tool`), falling back to the file
      with a one-time-per-process stderr warning when the keychain is
      locked or unavailable. A file key found while the keychain is
      available is also copied into the keychain (best-effort
      migration); the file stays as the fallback.
    - "keychain": same as auto, except the warning is the point: an
      operator who explicitly asked for the keychain wants to know when
      it is not engaged.
    - "file" (or any other value): the historical 0400 file only.
    The unattended poll path must keep working, so a locked or missing
    keychain NEVER blocks and NEVER prompts: it falls back, it warns
    once, and the run proceeds. First-time macOS access may prompt once
    at interactive setup; an unattended run that hits that prompt times
    out (10s) and falls back.
    Honest limits: the macOS path cannot be live-tested on this Linux
    VM (code-review only), and on a headless Linux box Secret Service
    is usually absent, so the file fallback is the normal path there."""
    global _KEYCHAIN_WARNED
    backend = os.environ.get("MUSE_RELAY_KEY_BACKEND", "auto")
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if backend in ("auto", "keychain"):
        key = _keychain_get()
        if key is not None:
            return key
        if os.path.exists(LOCAL_KEY_FILE):
            with open(LOCAL_KEY_FILE, "rb") as f:
                key = f.read()
            if len(key) != 32:
                raise ValueError("local key file is corrupt (not 32 bytes)")
            # Best-effort migration into the keychain; the file stays.
            _keychain_put(key)
            if not _KEYCHAIN_WARNED:
                _KEYCHAIN_WARNED = True
                print("warning: keychain unavailable, using local key file",
                      file=sys.stderr)
            return key
        key = secrets.token_bytes(32)
        _keychain_put(key)
        _write_local_key_file(key)
        return key
    if os.path.exists(LOCAL_KEY_FILE):
        with open(LOCAL_KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("local key file is corrupt (not 32 bytes)")
        return key
    key = secrets.token_bytes(32)
    _write_local_key_file(key)
    return key


def _encrypt_state(state: dict) -> dict:
    """Wrap a space-state dict in an AES-256-GCM envelope. The on-disk
    file never contains a space key, member private key, control seed, or
    pairing code in plaintext."""
    pt = json.dumps(state, sort_keys=True).encode()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_local_key()).encrypt(nonce, pt, None)
    return {"v": 2, "nonce": b64e(nonce), "ct": b64e(ct)}


def _decrypt_state(wrapper: dict) -> dict:
    pt = AESGCM(_local_key()).decrypt(
        b64d(wrapper["nonce"]), b64d(wrapper["ct"]), None)
    return json.loads(pt.decode())


def _write_private(path: str, data: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _space_path(space_id: str) -> str:
    return os.path.join(SPACES_DIR, space_id + ".json")


def save_space(s: dict):
    _write_private(_space_path(s["space_id"]), _encrypt_state(s))


def load_space(space_id: str) -> dict:
    path = _space_path(space_id)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and data.get("v") == 2:
        return _decrypt_state(data)
    # Plaintext v1 state: transparent one-time migration to encrypted form.
    # The original is kept as .bak and the encrypted rewrite is only kept
    # once it round-trips exactly; a failed migration restores the backup
    # and raises instead of leaving a half-migrated file behind.
    bak = path + ".bak"
    with open(bak, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.chmod(bak, 0o600)
    _write_private(path, _encrypt_state(data))
    with open(path, encoding="utf-8") as f:
        check = json.load(f)
    if _decrypt_state(check) != data:
        with open(bak, encoding="utf-8") as f:
            orig = f.read()
        with open(path, "w", encoding="utf-8") as f:
            f.write(orig)
        raise ValueError(
            "state migration failed verification; original restored from .bak")
    return data


def audit(space_id: str, entries):
    """Append decrypted messages to the per-space audit log (JSON lines)."""
    path = os.path.join(AUDIT_DIR, space_id + ".log")
    os.makedirs(AUDIT_DIR, exist_ok=True)
    seen = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    seen.add(json.loads(line)["id"])
                except (KeyError, ValueError):
                    pass
    new = [e for e in entries if e["id"] not in seen]
    if not new:
        return 0
    with open(path, "a", encoding="utf-8") as f:
        for e in new:
            f.write(json.dumps({
                "id": e["id"], "ts": e["ts"], "pubkey": e["pubkey"],
                "sig_ok": e["sig_ok"], "decrypt_ok": e["decrypt_ok"],
                "author": e.get("author"), "body": e.get("body"),
            }) + "\n")
    os.chmod(path, 0o600)
    return len(new)


# ---------------------------------------------------------------- roster history (anti-rollback)

def roster_hash(members) -> str:
    """Hash of a roster snapshot: sorted 'pubkey:display_name' lines.

    The hash is over public data (pubkeys and self-asserted names), so it
    is safe to persist and to show in warnings."""
    lines = sorted(f"{m['pubkey']}:{m.get('display_name', '')}"
                   for m in members)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def _roster_notices(prev, epoch: int, members, history):
    """Compare a fresh roster observation against recorded history.

    prev is the last recorded observation
    {"epoch", "hash", "members": [{"pubkey", "display_name"}]} or None.
    history is the list of past {"epoch", "hash"} observations.
    Returns (notices, observation) where notices is a list of
    {"level", "type", "detail"} dicts. Levels: 'warning' for rollback
    signals, 'notice' for ordinary roster changes.

    Rules (see PROTOCOL-V2.md, roster anti-rollback):
    - epoch decreases -> warning (a server-side rollback shows up here
      first, because a rolled-back space record carries its old epoch).
    - a member disappears without an epoch increase -> warning. A
      legitimate kick always bumps the epoch, so a disappearance at the
      same epoch means the server is hiding a member.
    - the roster hash returns to a previously seen hash while the epoch
      is at or below the epoch at which the previous roster was last
      seen -> warning. A legitimate kick that returns the roster to an
      earlier shape does NOT trip this: the kick bumps the epoch past
      the previous roster's epoch.
    - any other roster change -> plain notice. Roster changes are
      generic client behavior: every caller of members() sees them, not
      just polling integrations.

    Limits, stated plainly: a brand-new joiner has no history and cannot
    detect a rollback; and these checks catch a server showing stale
    state, not a server that invents a wholly new roster (that is what
    certificate verification is for)."""
    notices = []
    now_hash = roster_hash(members)
    now_pubkeys = {m["pubkey"] for m in members}
    if prev is None:
        return notices, {"epoch": epoch, "hash": now_hash,
                         "members": [{"pubkey": m["pubkey"],
                                      "display_name": m.get("display_name", "")}
                                     for m in members]}
    prev_epoch = prev["epoch"]
    prev_hash = prev["hash"]
    prev_pubkeys = {m["pubkey"] for m in prev["members"]}
    prev_names = {m["pubkey"]: m.get("display_name", "")
                  for m in prev["members"]}
    if epoch < prev_epoch:
        notices.append({"level": "warning", "type": "epoch_decreased",
                        "detail": f"epoch decreased {prev_epoch} -> {epoch} "
                                  f"(possible rollback)"})
    vanished = prev_pubkeys - now_pubkeys
    if vanished and epoch <= prev_epoch:
        names = ", ".join(
            f"{prev_names.get(p, '?')} · {short_fp(p)}"
            for p in sorted(vanished))
        notices.append({"level": "warning", "type": "member_vanished",
                        "detail": f"member(s) disappeared without an epoch "
                                  f"increase: {names} (possible rollback)"})
    if now_hash != prev_hash:
        joined = now_pubkeys - prev_pubkeys
        left = prev_pubkeys - now_pubkeys
        parts = []
        if joined:
            names = ", ".join(
                f"{next(m.get('display_name', '') for m in members if m['pubkey'] == p)} · {short_fp(p)}"
                for p in sorted(joined))
            parts.append(f"joined {names}")
        if left:
            names = ", ".join(
                f"{prev_names.get(p, '?')} · {short_fp(p)}"
                for p in sorted(left))
            parts.append(f"left {names}")
        if not parts:
            parts.append("roster changed (names or keys differ)")
        # Revert check: the new hash was seen before, and the epoch is
        # at or below the epoch at which the PREVIOUS roster was last
        # observed. A kick returning the roster to an earlier shape
        # bumps the epoch past that point, so it does not trip this.
        prev_last_epoch = prev_epoch
        for entry in history:
            if entry.get("hash") == prev_hash:
                prev_last_epoch = max(prev_last_epoch,
                                      entry.get("epoch", 0))
        seen_hashes = {e.get("hash") for e in history}
        if now_hash in seen_hashes and epoch <= prev_last_epoch:
            notices.append({"level": "warning", "type": "roster_reverted",
                            "detail": "roster reverted to a previously seen "
                                      "state (possible rollback)"})
        else:
            notices.append({"level": "notice", "type": "roster_changed",
                            "detail": "roster changed: " + "; ".join(parts),
                            "joined": sorted(joined),
                            "left": sorted(left)})
    return notices, {"epoch": epoch, "hash": now_hash,
                     "members": [{"pubkey": m["pubkey"],
                                  "display_name": m.get("display_name", "")}
                                 for m in members]}


def _audit_notice(space_id: str, notice):
    """Record a roster notice in the per-space audit log (best effort).

    Notice lines carry no 'id', so audit()'s seen-set computation skips
    them; they never disturb message dedup."""
    try:
        path = os.path.join(AUDIT_DIR, space_id + ".log")
        os.makedirs(AUDIT_DIR, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "type": "roster-notice", "ts": int(time.time() * 1000),
                "level": notice["level"], "notice_type": notice["type"],
                "detail": notice["detail"],
            }) + "\n")
        os.chmod(path, 0o600)
    except Exception:
        pass


def _record_roster(space_id: str, epoch: int, members):
    """Record a roster observation in the local space state and return
    any notices it raises. Never raises: history bookkeeping must not
    break a roster read (fetch/send flows depend on members())."""
    try:
        s = load_space(space_id)
    except Exception as e:
        return [{"level": "warning", "type": "history_error",
                 "detail": f"roster history could not be recorded: {e}"}]
    try:
        prev = s.get("roster_last")
        history = s.get("roster_history", [])
        notices, observation = _roster_notices(prev, epoch, members,
                                               history)
        s["roster_last"] = observation
        last = history[-1] if history else None
        if (last is None or last.get("hash") != observation["hash"]
                or last.get("epoch") != observation["epoch"]):
            history = history + [{"epoch": observation["epoch"],
                                  "hash": observation["hash"]}]
            s["roster_history"] = history[-50:]
        save_space(s)
        for n in notices:
            _audit_notice(space_id, n)
        return notices
    except Exception as e:
        return [{"level": "warning", "type": "history_error",
                 "detail": f"roster history could not be recorded: {e}"}]


def _save_merged(s: dict):
    """Save space state, preserving roster-history keys written by a
    nested members() call after s was loaded. members() records roster
    observations in the state file; a caller that later saves its own
    stale in-memory copy must not clobber them. Best effort: on any
    load failure the caller's copy is saved as-is."""
    try:
        fresh = load_space(s["space_id"])
        for k in ("roster_last", "roster_history"):
            if k in fresh:
                s[k] = fresh[k]
    except Exception:
        pass
    save_space(s)


# ---------------------------------------------------------------- API

class Relay:
    def __init__(self, base: str = DEFAULT_BASE):
        self.base = base.rstrip("/")

    def _req(self, method: str, path: str, body=None, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "content-type": "application/json",
            # Cloudflare blocks the default "Python-urllib/..." UA (error 1010).
            "user-agent": "MuseRelay/1.0 (+https://github.com/cruciferousgreens/muse-relay)",
        }
        # Cloudflare's bot mitigation sometimes RSTs rapid successive POSTs
        # from non-browser TLS fingerprints; back off and retry.
        last = None
        for attempt in range(4):
            req = urllib.request.Request(url, data=data, method=method,
                                         headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as e:
                try:
                    err = json.load(e)
                except Exception:
                    err = {"error": f"http {e.code}"}
                if e.code in (429, 500, 502, 503) and attempt < 3:
                    last = RuntimeError(err.get("error", f"http {e.code}"))
                else:
                    raise RuntimeError(err.get("error", f"http {e.code}")) from None
            except (ConnectionError, TimeoutError, OSError) as e:
                last = e
            if attempt < 3:
                time.sleep(2 ** attempt)
        raise RuntimeError(f"request failed after retries: {last}")

    def create(self, display_name: str) -> dict:
        space_id = b64e(secrets.token_bytes(16))
        space_key = secrets.token_bytes(32)
        words = gen_code_words(8)
        lookup = derive_lookup(words)
        kek = derive_kek(words, lookup)
        wrapped = wrap_space_key(kek, space_key)
        ctrl_seed_b64, ctrl_pub_b64 = gen_control_keypair()
        wrapped_control = wrap_control_seed(space_key, ctrl_seed_b64)
        pub_b64, priv_b64 = gen_member_keypair()
        # The creator's X25519 keypair doubles as the admin wrapping key:
        # the admin wraps each remaining member's epoch-key copy with
        # ECDH(admin_priv, member_x_pub), and unwraps its own copy the same
        # way. Members created by this client always carry an x_pubkey, so
        # a space created here is rotation-capable from birth.
        x_pub_b64, x_priv_b64 = gen_member_x_keypair()
        cert = sign_member_cert(ctrl_seed_b64, space_id, pub_b64, display_name)
        try:
            self._req("POST", "/api/spaces", {
                "space_id": space_id, "lookup": lookup, "wrapped": wrapped,
                "wrapped_control": wrapped_control, "control_pub": ctrl_pub_b64,
                "display_name": display_name, "pubkey": pub_b64, "cert": cert,
                "x_pubkey": x_pub_b64,
            })
        except RuntimeError as e:
            # Our own retried POST can land after the original succeeded
            # (response lost to a RST). Same id + same body means the stored
            # space is exactly what we sent — treat it as created.
            if "space exists" not in str(e):
                raise
        s = {
            "space_id": space_id, "key_b64": b64e(space_key),
            "code": " ".join(words),
            "link": f"{self.base}/s/{space_id}#k={b64e(space_key)}",
            "member": {"pub_b64": pub_b64, "priv_b64": priv_b64,
                       "x_pub_b64": x_pub_b64, "x_priv_b64": x_priv_b64},
            "display_name": display_name,
            "control_pub": ctrl_pub_b64,  # pinned: derived from the seed we minted
            # Creator only: the control seed signs kicks and epoch bundles.
            # Joiners never hold it, so only the creator can kick/rotate.
            # (Spaces created by older clients have no stored seed here and
            # therefore cannot kick — rotation is a new-space capability.)
            "control_seed": ctrl_seed_b64,
            "epoch": 0,
            "epoch_key_b64": None,
        }
        save_space(s)
        return s

    def _register(self, space_id: str, ctrl_seed_b64: str,
                  display_name: str) -> dict:
        pub_b64, priv_b64 = gen_member_keypair()
        x_pub_b64, x_priv_b64 = gen_member_x_keypair()
        cert = sign_member_cert(ctrl_seed_b64, space_id, pub_b64, display_name)
        self._req("POST", f"/api/spaces/{space_id}/members",
                  {"display_name": display_name, "pubkey": pub_b64,
                   "cert": cert, "x_pubkey": x_pub_b64})
        return {"pub_b64": pub_b64, "priv_b64": priv_b64,
                "x_pub_b64": x_pub_b64, "x_priv_b64": x_priv_b64}

    def join_code(self, code: str, display_name: str,
                  expect_control_fp=None) -> dict:
        words = code.strip().lower().split()
        if len(words) != 8:
            raise ValueError("code must be 8 words")
        lookup = derive_lookup(words)
        data = self._req("POST", "/api/spaces/join", {"lookup": lookup})
        kek = derive_kek(words, lookup)
        space_key = unwrap_space_key(kek, data["wrapped"])
        ctrl_seed = unwrap_control_seed(space_key, data["wrapped_control"])
        # Pin the control key: it must equal the server's claimed control_pub.
        # If the server substituted a different control_pub, abort — its
        # rogue member certificates must never be trusted.
        ctrl_pub = control_pub_from_seed(ctrl_seed)
        if data.get("control_pub") != ctrl_pub:
            raise RuntimeError("control key mismatch: server's control_pub does "
                               "not match the unwrapped control seed")
        # Optional second-channel pinning (see check_control_fp).
        check_control_fp(ctrl_pub, expect_control_fp)
        member = self._register(data["space_id"], ctrl_seed, display_name)
        s = {
            "space_id": data["space_id"], "key_b64": b64e(space_key),
            "code": " ".join(words),
            "link": f"{self.base}/s/{data['space_id']}#k={b64e(space_key)}",
            "member": member,
            "display_name": display_name,
            "control_pub": ctrl_pub,
            "epoch": 0,
            "epoch_key_b64": None,
        }
        save_space(s)
        return s

    def join_link(self, link: str, display_name: str,
                  expect_control_fp=None) -> dict:
        if "#k=" not in link:
            raise ValueError("not a Muse Relay link (missing #k= fragment)")
        head, key_b64 = link.split("#k=", 1)
        space_id = head.rstrip("/").rsplit("/s/", 1)[-1]
        if len(space_id) != 22:
            raise ValueError("not a Muse Relay link (bad space id)")
        space_key = b64d(key_b64)
        ctrl = self._req("GET", f"/api/spaces/{space_id}/control")
        ctrl_seed = unwrap_control_seed(space_key, ctrl["wrapped_control"])
        ctrl_pub = control_pub_from_seed(ctrl_seed)
        if ctrl.get("control_pub") != ctrl_pub:
            raise RuntimeError("control key mismatch: server's control_pub does "
                               "not match the unwrapped control seed")
        # Optional second-channel pinning (see check_control_fp).
        check_control_fp(ctrl_pub, expect_control_fp)
        member = self._register(space_id, ctrl_seed, display_name)
        s = {
            "space_id": space_id, "key_b64": key_b64, "code": None,
            "link": link,
            "member": member,
            "display_name": display_name,
            "control_pub": ctrl_pub,
            "epoch": 0,
            "epoch_key_b64": None,
        }
        save_space(s)
        return s

    def members(self, space_id: str):
        # Roster certificates are verified against the PINNED control key from
        # local state — never blindly against a fresh server-supplied
        # control_pub, which a tampering server could swap to get rogue
        # member certificates trusted.
        s = load_space(space_id)
        ctrl_pub = s.get("control_pub")
        if not ctrl_pub:
            # Trust-on-first-use migration for states saved before pinning
            # existed: pin the server's current key going forward.
            ctrl_pub = self._req(
                "GET", f"/api/spaces/{space_id}/control")["control_pub"]
            s["control_pub"] = ctrl_pub
            save_space(s)
        resp = self._req("GET", f"/api/spaces/{space_id}/members")
        data = resp["members"]
        for m in data:
            m["cert_ok"] = verify_member_cert(
                ctrl_pub, space_id, m["pubkey"], m["display_name"], m["cert"])
        # The server epoch rides along so kick/rotate know what the next
        # epoch number must be. Old servers omit it; epoch 0 is the safe
        # reading of "no rotation has happened".
        # Roster anti-rollback: every roster read is recorded in local
        # state and compared against history; see _record_roster. The
        # notices are returned (and printed by the CLI) as generic client
        # behavior, not just polling policy.
        notices = _record_roster(space_id, resp.get("epoch", 0), data)
        return {"members": data, "epoch": resp.get("epoch", 0),
                "notices": notices}

    def send(self, space_id: str, body: str):
        s = load_space(space_id)
        epoch = s.get("epoch", 0)
        # Client-generated message id: _req retries resend the same body, and
        # the server dedupes on the id instead of double-posting.
        msg_id = (f"{int(time.time() * 1000):015d}-"
                  f"{_b36(secrets.randbelow(46656))}")
        if epoch >= 1:
            # Rotated space: v2 only, under the epoch key. Refusing to fall
            # back to v1 here is deliberate — a v1 message is encrypted
            # under the long-lived space key, which a kicked member still
            # holds, so a silent fallback would silently defeat the kick.
            if not s.get("epoch_key_b64"):
                raise RuntimeError(
                    f"space is at epoch {epoch} but this device has no epoch "
                    "key — run `rotate` first")
            key = b64d(s["epoch_key_b64"])
            nonce, ct = encrypt_message(key, s["display_name"], body)
            sig = sign_message_v2(s["member"]["priv_b64"], space_id, epoch,
                                  nonce, ct)
            msg_body = {
                "id": msg_id, "ciphertext": ct, "nonce": nonce,
                "pubkey": s["member"]["pub_b64"], "signature": sig,
                "version": 2, "epoch": epoch,
            }
            # The server may briefly lag behind this device after a kick
            # (KV reads are eventually consistent): it can reject a v2
            # message as "stale epoch" while its own view catches up.
            # The message id is client-generated and server-deduped, so
            # retrying the identical POST cannot double-post. If the
            # server is actually AHEAD of this device, fail fast with a
            # rotate-first error instead of retrying.
            for attempt in range(3):
                try:
                    return self._req(
                        "POST", f"/api/spaces/{space_id}/messages", msg_body)
                except RuntimeError as e:
                    if "stale epoch" not in str(e):
                        raise
                    try:
                        server_epoch = self.members(space_id).get("epoch", 0)
                    except Exception:
                        server_epoch = None
                    if (server_epoch is not None
                            and server_epoch > epoch):
                        raise RuntimeError(
                            f"space is at epoch {server_epoch} but this "
                            f"device is at epoch {epoch} — run `rotate` "
                            "first") from None
                    if attempt == 2:
                        raise
                    time.sleep(2 ** attempt)
        key = b64d(s["key_b64"])
        nonce, ct = encrypt_message(key, s["display_name"], body)
        sig = sign_message(s["member"]["priv_b64"], space_id, nonce, ct)
        return self._req("POST", f"/api/spaces/{space_id}/messages", {
            "id": msg_id, "ciphertext": ct, "nonce": nonce,
            "pubkey": s["member"]["pub_b64"], "signature": sig,
        })

    def fetch(self, space_id: str, since: str = "", limit: int = 50,
              audit_log: bool = True):
        s = load_space(space_id)
        key = b64d(s["key_b64"])
        # Roster for display-name binding. Best effort: if the roster fetch
        # fails, every name falls back to a clearly-marked unverified form
        # instead of silently trusting the self-asserted author field.
        # Roster notices (anti-rollback) go to stderr: pollers capture
        # stdout, warnings belong on the other channel.
        roster = {}
        try:
            resp = self.members(space_id)
            for n in resp.get("notices", []):
                print(f"roster {n['level']}: {n['detail']}",
                      file=sys.stderr)
            for m in resp["members"]:
                roster[m["pubkey"]] = (m["display_name"], bool(m.get("cert_ok")))
        except Exception:
            roster = {}
        data = self._req("GET", f"/api/spaces/{space_id}/messages",
                         params={"since": since, "limit": limit})
        out = []
        for m in data["messages"]:
            version = m.get("version", 1)
            msg_epoch = m.get("epoch", 0)
            if version == 2:
                sig_ok = verify_message_v2(
                    m["pubkey"], space_id, msg_epoch,
                    m["nonce"], m["ciphertext"], m["signature"])
            else:
                sig_ok = verify_message(m["pubkey"], space_id, m["nonce"],
                                        m["ciphertext"], m["signature"])
            decrypt_ok, author, body, note = True, None, None, None
            if version == 2:
                if (s.get("epoch", 0) == msg_epoch
                        and s.get("epoch_key_b64")):
                    try:
                        pt = decrypt_message(b64d(s["epoch_key_b64"]),
                                             m["nonce"], m["ciphertext"])
                        author, body = pt.get("author"), pt.get("body")
                    except Exception:
                        decrypt_ok = False
                else:
                    # Epoch key missing or stale: never guess, never show
                    # ciphertext as if it were text. The user-visible note
                    # says exactly what to do about it.
                    decrypt_ok = False
                    note = (f"v2 message from epoch {msg_epoch}; this device "
                            f"is at epoch {s.get('epoch', 0)} — run `rotate` "
                            "to fetch the current epoch key")
            else:
                # v1 messages use the space key. After a link-key
                # rotation the current key no longer opens pre-rotation
                # messages, so try the retained key history too.
                # Rotation is forward-only by design: old keys still
                # decrypt old messages.
                pt = None
                candidate_keys = [key]
                for h in s.get("key_history_b64", []):
                    try:
                        candidate_keys.append(b64d(h))
                    except Exception:
                        continue
                for k in candidate_keys:
                    try:
                        pt = decrypt_message(k, m["nonce"],
                                             m["ciphertext"])
                        break
                    except Exception:
                        continue
                if pt is None:
                    decrypt_ok = False
                else:
                    author, body = pt.get("author"), pt.get("body")
            display, display_ok = resolve_author(m["pubkey"], roster, author)
            out.append({**m, "sig_ok": sig_ok, "decrypt_ok": decrypt_ok,
                        "author": author, "body": body,
                        "author_display": display,
                        "author_fp": short_fp(m["pubkey"]),
                        "author_verified": display_ok,
                        "note": note,
                        "mine": m["pubkey"] == s["member"]["pub_b64"]})
        if audit_log and out:
            audit(space_id, out)
        return out

    def _wrap_epoch_key(self, space_id: str, roster, skip_pub_b64,
                          epoch_key: bytes, epoch: int, s: dict):
        """Wrap an epoch key for every roster member with an X25519 key,
        except skip_pub_b64 (the kicked member, or None for all).
        Returns (wrapped, left_behind): members without an X25519 key are
        listed, not wrapped — they stay on v1 until they rejoin."""
        wrapped, left_behind = [], []
        for m in roster:
            if m["pubkey"] == skip_pub_b64:
                continue
            if not m.get("x_pubkey"):
                left_behind.append(m["display_name"])
                continue
            shared = ecdh_shared(s["member"]["x_priv_b64"], m["x_pubkey"])
            wk = epoch_wrapping_key(shared, space_id, epoch)
            wrapped.append({"pubkey": m["pubkey"],
                            "wrapped": wrap_epoch_key(wk, epoch_key)})
        return wrapped, left_behind

    def _publish_bundle(self, space_id: str, epoch: int, epoch_key: bytes,
                          s: dict, roster):
        """Upload a wrapped epoch-key bundle for the CURRENT epoch
        (the republish endpoint). The server re-validates every entry
        against the current roster before storing."""
        wrapped, _ = self._wrap_epoch_key(
            space_id, roster, None, epoch_key, epoch, s)
        self._req("POST", f"/api/spaces/{space_id}/epoch-keys",
                  {"epoch": epoch,
                   "admin_x_pub": s["member"]["x_pub_b64"],
                   "keys": wrapped,
                   "signature": sign_epoch_bundle(
                       s["control_seed"], space_id, epoch)})

    def kick(self, space_id: str, target_pub_b64: str):
        """Remove a member and rotate the epoch key. Creator only.

        Returns {"epoch", "kicked", "left_behind"} and prints nothing itself;
        the CLI reports the warnings. Read them — they are the honest limits
        of this feature:
        - The kicked member keeps every pre-kick epoch key and can still
          read every message from epochs before the kick.
        - Any v1 message — including future ones sent by legacy clients
          that have not rotated — stays readable to the kicked member,
          because v1 uses the long-lived space key they already hold.
        - Remaining members WITHOUT an x_pubkey (joined with a pre-rotation
          client) cannot receive the new epoch key and are left on v1 until
          they rejoin with a rotation-capable client. They are listed in
          left_behind; they are NOT kicked, they just cannot read v2."""
        s = load_space(space_id)
        if not s.get("control_seed"):
            raise RuntimeError(
                "this device is not the space creator (no control seed "
                "stored) — only the creator can kick")
        if not s["member"].get("x_priv_b64"):
            raise RuntimeError(
                "this device has no X25519 member key — rejoin with a "
                "rotation-capable client first")
        resp = self.members(space_id)
        roster = resp["members"]
        server_epoch = resp.get("epoch", 0)
        target = next((m for m in roster if m["pubkey"] == target_pub_b64),
                      None)
        if target is None:
            raise RuntimeError("no such member in this space")
        if target_pub_b64 == s["member"]["pub_b64"]:
            raise RuntimeError("refusing to kick yourself")
        new_epoch = server_epoch + 1
        # Client-side pre-check of the exact rule the server re-checks.
        validate_kick_request(
            [m["pubkey"] for m in roster], s["control_pub"], space_id,
            server_epoch, target_pub_b64, new_epoch,
            sign_kick(s["control_seed"], space_id, target_pub_b64, new_epoch))
        epoch_key = secrets.token_bytes(32)
        # Save the pending epoch BEFORE any network call: if the kick
        # POST succeeds but its response is lost (RST/timeout), the key
        # survives locally and republish() can heal the bundle instead of
        # leaving the space kicked-but-keyless.
        s["pending_epoch"] = {"epoch": new_epoch,
                              "key_b64": b64e(epoch_key)}
        _save_merged(s)
        wrapped, left_behind = self._wrap_epoch_key(
            space_id, roster, target_pub_b64, epoch_key, new_epoch, s)
        # ATOMIC kick: the removal and the wrapped epoch keys travel in
        # ONE request and land in ONE server-side write. The old two-step
        # flow broke under KV eventual consistency: the bundle upload
        # could be served from a colo that had not seen the kick yet and
        # fail, leaving the space kicked-but-keyless.
        body = {"pubkey": target_pub_b64, "epoch": new_epoch,
                "signature": sign_kick(
                    s["control_seed"], space_id, target_pub_b64, new_epoch),
                "keys": wrapped,
                "admin_x_pub": s["member"]["x_pub_b64"],
                "epoch_signature": sign_epoch_bundle(
                    s["control_seed"], space_id, new_epoch)}
        try:
            self._req("POST", f"/api/spaces/{space_id}/kick", body)
        except RuntimeError as e:
            if "stale epoch" not in str(e):
                raise
            # Maybe our kick already applied and the response was lost.
            # Re-read: if the target is gone and the server sits exactly
            # at our new epoch, heal by republishing from the pending key.
            resp2 = self.members(space_id)
            if (resp2.get("epoch", 0) == new_epoch and
                    not any(m["pubkey"] == target_pub_b64
                            for m in resp2["members"])):
                self._publish_bundle(space_id, new_epoch, epoch_key, s,
                                     resp2["members"])
                s["epoch"] = new_epoch
                s["epoch_key_b64"] = b64e(epoch_key)
                s.pop("pending_epoch", None)
                _save_merged(s)
                return {"epoch": new_epoch,
                        "kicked": target["display_name"],
                        "left_behind": left_behind, "recovered": True}
            raise
        s["epoch"] = new_epoch
        s["epoch_key_b64"] = b64e(epoch_key)
        s.pop("pending_epoch", None)
        _save_merged(s)
        return {"epoch": new_epoch, "kicked": target["display_name"],
                "left_behind": left_behind}

    def republish(self, space_id: str):
        """Re-publish the wrapped epoch-key bundle for the CURRENT epoch.
        Creator only. Recovery for a bundle that never landed (e.g. an
        interrupted kick): if a pending key from a kick exists for this
        epoch it is reused; if this device already holds the current
        epoch key that is reused; otherwise a fresh key is generated and
        becomes the current epoch key. Members re-run `rotate` after."""
        s = load_space(space_id)
        if not s.get("control_seed"):
            raise RuntimeError(
                "only the space creator can republish epoch keys")
        resp = self.members(space_id)
        server_epoch = resp.get("epoch", 0)
        if server_epoch == 0:
            return {"epoch": 0, "published": False}
        pending = s.get("pending_epoch") or {}
        if pending.get("epoch") == server_epoch and pending.get("key_b64"):
            epoch_key = b64d(pending["key_b64"])
        elif (s.get("epoch") == server_epoch
                and s.get("epoch_key_b64")):
            epoch_key = b64d(s["epoch_key_b64"])
        else:
            epoch_key = secrets.token_bytes(32)
        self._publish_bundle(space_id, server_epoch, epoch_key, s,
                             resp["members"])
        s["epoch"] = server_epoch
        s["epoch_key_b64"] = b64e(epoch_key)
        s.pop("pending_epoch", None)
        _save_merged(s)
        return {"epoch": server_epoch, "published": True}

    def rotate(self, space_id: str):
        """Fetch the current epoch key after a kick. Returns {"epoch",
        "rotated"}. Raises when this device cannot rotate: no X25519 key
        (joined with a pre-rotation client), no longer a member, or no
        wrapped key published for it."""
        s = load_space(space_id)
        if not s["member"].get("x_priv_b64"):
            raise RuntimeError(
                "this device has no X25519 member key — it joined with a "
                "pre-rotation client; rejoin to get one")
        resp = self.members(space_id)
        server_epoch = resp.get("epoch", 0)
        bundle = None
        if server_epoch <= s.get("epoch", 0):
            # The members read may lag the true epoch (KV eventual
            # consistency); the bundle is a second, independent read
            # that can reveal an advance the first read missed.
            try:
                bundle = self._req(
                    "GET", f"/api/spaces/{space_id}/epoch-keys")
            except Exception:
                bundle = None
            if bundle and bundle.get("epoch", 0) > s.get("epoch", 0):
                server_epoch = bundle["epoch"]
            else:
                return {"epoch": s.get("epoch", 0), "rotated": False}
        if not any(m["pubkey"] == s["member"]["pub_b64"]
                   for m in resp["members"]):
            raise RuntimeError("you are no longer a member of this space")
        if bundle is None:
            bundle = self._req("GET", f"/api/spaces/{space_id}/epoch-keys")
        if bundle.get("epoch") != server_epoch:
            raise RuntimeError("epoch-keys bundle is stale; try again")
        entry = next((k for k in bundle.get("keys", [])
                      if k["pubkey"] == s["member"]["pub_b64"]), None)
        if entry is None:
            raise RuntimeError(
                "no wrapped epoch key for this device — it may have joined "
                "without an X25519 key; rejoin with a rotation-capable client")
        shared = ecdh_shared(s["member"]["x_priv_b64"], bundle["admin_x_pub"])
        wk = epoch_wrapping_key(shared, space_id, server_epoch)
        epoch_key = unwrap_epoch_key(wk, entry["wrapped"])
        s["epoch"] = server_epoch
        s["epoch_key_b64"] = b64e(epoch_key)
        _save_merged(s)
        return {"epoch": server_epoch, "rotated": True}

    def _control_seed_for(self, s: dict, space_id: str) -> str:
        """Obtain the control seed for admin operations. The creator
        stores it in local state; anyone else holding the 8-word code
        can derive it through the code-unwrap chain (which is exactly
        why seed holders — not just 'the creator' — hold admin rights).
        Raises RuntimeError if neither is available."""
        if s.get("control_seed"):
            return s["control_seed"]
        if s.get("code"):
            words = s["code"].split()
            lookup = derive_lookup(words)
            data = self._req("POST", "/api/spaces/join", {"lookup": lookup})
            kek = derive_kek(words, lookup)
            space_key = unwrap_space_key(kek, data["wrapped"])
            return unwrap_control_seed(space_key, data["wrapped_control"])
        raise RuntimeError(
            "need the control seed or the 8-word code for this operation")

    def rotate_key(self, space_id: str):
        """Rotate the link key (the join credential). Needs the control
        seed (for the rotation signature) and the 8-word code (to
        re-wrap the code-path blob — otherwise code joins would still
        yield the old key).

        FORWARD-ONLY, like kick: the old link can no longer join, but
        existing members are NOT evicted (use kick for that) and old v1
        messages stay readable — the old key is retained in local key
        history so this device can still decrypt them. Epoch and members
        are untouched. Returns {"space_id", "link", "epoch"}; the CLI
        prints the new link (distribute it through the usual channel)
        and the epoch-0 warning."""
        s = load_space(space_id)
        if not s.get("code"):
            raise RuntimeError(
                "need the 8-word code to rotate the link key: the "
                "code-path wrapped blob must be re-wrapped under the new "
                "key, or code joins would still yield the old key")
        seed = self._control_seed_for(s, space_id)
        words = s["code"].split()
        lookup = derive_lookup(words)
        kek = derive_kek(words, lookup)
        new_key = secrets.token_bytes(32)
        new_wrapped_control = wrap_control_seed(new_key, seed)
        new_wrapped = wrap_space_key(kek, new_key)
        sig = sign_rotate_key(seed, space_id,
                              new_wrapped_control, new_wrapped)
        self._req("POST", f"/api/spaces/{space_id}/rotate-key",
                  {"wrapped_control": new_wrapped_control,
                   "wrapped": new_wrapped, "signature": sig})
        history = [s["key_b64"]] + s.get("key_history_b64", [])
        s["key_history_b64"] = history[:5]
        s["key_b64"] = b64e(new_key)
        s["link"] = f"{self.base}/s/{space_id}#k={b64e(new_key)}"
        save_space(s)
        return {"space_id": space_id, "link": s["link"],
                "epoch": s.get("epoch", 0)}

    def rotate_epoch(self, space_id: str):
        """Advance the epoch key WITHOUT removing anyone (kickless
        rotation). Needs the control seed (signature) and an X25519
        member key (wrapping); any seed holder can do it, under the
        same honest model as kick. Members re-run `rotate` to fetch
        the new key, exactly as after a kick. Returns {"epoch",
        "left_behind"} (members without an X25519 key stay on v1).
        Weekly use: run this on a schedule to shrink each epoch's blast
        radius — it is the command the weekly-rotation cron calls."""
        s = load_space(space_id)
        seed = self._control_seed_for(s, space_id)
        if not s["member"].get("x_priv_b64"):
            raise RuntimeError(
                "this device has no X25519 member key — rejoin with a "
                "rotation-capable client first")
        resp = self.members(space_id)
        roster = resp["members"]
        server_epoch = resp.get("epoch", 0)
        new_epoch = server_epoch + 1
        epoch_key = secrets.token_bytes(32)
        # Save the pending epoch BEFORE any network call (same RST
        # reasoning as kick): a lost response must not leave the space
        # rotated-but-keyless locally.
        s["pending_epoch"] = {"epoch": new_epoch,
                              "key_b64": b64e(epoch_key)}
        _save_merged(s)
        wrapped, left_behind = self._wrap_epoch_key(
            space_id, roster, None, epoch_key, new_epoch, s)
        body = {"epoch": new_epoch, "keys": wrapped,
                "admin_x_pub": s["member"]["x_pub_b64"],
                "signature": sign_epoch_bundle(seed, space_id, new_epoch)}
        try:
            self._req("POST", f"/api/spaces/{space_id}/rotate-epoch", body)
        except RuntimeError as e:
            if "stale epoch" not in str(e):
                raise
            # Maybe our rotation already applied and the response was
            # lost. Heal by republishing the bundle for the new epoch.
            resp2 = self.members(space_id)
            if resp2.get("epoch", 0) == new_epoch:
                self._req("POST", f"/api/spaces/{space_id}/epoch-keys",
                          {"epoch": new_epoch,
                           "admin_x_pub": s["member"]["x_pub_b64"],
                           "keys": wrapped,
                           "signature": sign_epoch_bundle(
                               seed, space_id, new_epoch)})
                s["epoch"] = new_epoch
                s["epoch_key_b64"] = b64e(epoch_key)
                s.pop("pending_epoch", None)
                _save_merged(s)
                return {"epoch": new_epoch, "left_behind": left_behind,
                        "recovered": True}
            raise
        s["epoch"] = new_epoch
        s["epoch_key_b64"] = b64e(epoch_key)
        s.pop("pending_epoch", None)
        _save_merged(s)
        return {"epoch": new_epoch, "left_behind": left_behind}

    def delete(self, space_id: str):
        s = load_space(space_id)
        if not s.get("code"):
            raise ValueError("need the 8-word code to delete (link joins can't delete)")
        words = s["code"].split()
        lookup = derive_lookup(words)
        try:
            return self._req("DELETE", f"/api/spaces/{space_id}", {"lookup": lookup})
        except RuntimeError as e:
            # A retried DELETE can land after the original succeeded (response
            # lost). "unknown space" then means the goal state — gone.
            if "unknown space" not in str(e):
                raise
            return {"ok": True, "already_gone": True}


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="relay.py", description="Muse Relay agent helper")
    ap.add_argument("--base", default=DEFAULT_BASE)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("create"); p.add_argument("--name", required=True)
    p = sub.add_parser("join-code"); p.add_argument("code"); p.add_argument("--name", required=True)
    p.add_argument("--expect-control-fp", default=None,
                   help="pin the control pubkey: full base64url pubkey or its "
                        "short fingerprint. The fingerprint MUST arrive via a "
                        "second channel (in-band with the link it adds "
                        "nothing); see check_control_fp.")
    p = sub.add_parser("join-link"); p.add_argument("link"); p.add_argument("--name", required=True)
    p.add_argument("--expect-control-fp", default=None,
                   help="pin the control pubkey: full base64url pubkey or its "
                        "short fingerprint. The fingerprint MUST arrive via a "
                        "second channel (in-band with the link it adds "
                        "nothing); see check_control_fp.")
    p = sub.add_parser("send"); p.add_argument("space_id"); p.add_argument("body")
    p = sub.add_parser("fetch"); p.add_argument("space_id"); p.add_argument("--since", default="")
    p = sub.add_parser("members"); p.add_argument("space_id")
    p = sub.add_parser("kick"); p.add_argument("space_id"); p.add_argument("pubkey")
    p = sub.add_parser("republish"); p.add_argument("space_id")
    p = sub.add_parser("rotate"); p.add_argument("space_id")
    p = sub.add_parser("rotate-key"); p.add_argument("space_id")
    p = sub.add_parser("rotate-epoch"); p.add_argument("space_id")
    p = sub.add_parser("delete"); p.add_argument("space_id")

    a = ap.parse_args(argv)
    if not a.base:
        print("error: set the relay server with --base or MUSE_RELAY_BASE",
              file=sys.stderr)
        return 2
    r = Relay(a.base)
    try:
        if a.cmd == "create":
            s = r.create(a.name)
            print(f"space:  {s['space_id']}")
            print(f"link:   {s['link']}")
            print(f"code:   {s['code']}")
        elif a.cmd == "join-code":
            s = r.join_code(a.code, a.name, a.expect_control_fp)
            print(f"joined: {s['space_id']}")
        elif a.cmd == "join-link":
            s = r.join_link(a.link, a.name, a.expect_control_fp)
            print(f"joined: {s['space_id']}")
        elif a.cmd == "send":
            m = r.send(a.space_id, a.body)
            print(f"sent:   {m['id']}")
        elif a.cmd == "fetch":
            msgs = r.fetch(a.space_id, since=a.since)
            for m in msgs:
                # A message is shown only when its signature verifies AND it
                # decrypts. Anything else is reported as an arrival, never
                # as content — a failed signature means the bytes are not
                # trustworthy, whatever they decrypt to. The fingerprint
                # after the name tells duplicate display names apart.
                if m["sig_ok"] and m["decrypt_ok"]:
                    vtag = " v1" if m.get("version", 1) == 1 else ""
                    print(f"[✓{vtag}] {m['author_display']} · "
                          f"{short_fp(m['pubkey'])}: {m['body']}")
                elif m.get("note"):
                    print(f"[!] {m['note']} (content withheld)")
                elif not m["sig_ok"]:
                    print("[!] message failed signature verification "
                          "(content withheld)")
                else:
                    print("[!] message could not be decrypted "
                          "(content withheld)")
            if not msgs:
                print("(no new messages)")
        elif a.cmd == "members":
            resp = r.members(a.space_id)
            for m in resp["members"]:
                flag = {True: "✓", False: "!", None: "?"}[m["cert_ok"]]
                vtag = " [v1]" if not m.get("x_pubkey") else ""
                print(f"[{flag}] {m['display_name']} · "
                      f"{short_fp(m['pubkey'])}{vtag}")
            print(f"epoch: {resp['epoch']}")
            for n in resp.get("notices", []):
                print(f"roster {n['level']}: {n['detail']}",
                      file=sys.stderr)
        elif a.cmd == "kick":
            res = r.kick(a.space_id, a.pubkey)
            print(f"kicked {res['kicked']} — space is now at epoch "
                  f"{res['epoch']}")
            print("WARNING: the kicked member can still read every message "
                  "from epochs before this kick.")
            print("WARNING: v1 messages (including future ones from legacy "
                  "clients) stay readable to them — exclusion covers v2 "
                  "epochs only.")
            if res["left_behind"]:
                print("left on v1 (no X25519 key — rejoin to rotate): "
                      + ", ".join(res["left_behind"]))
        elif a.cmd == "republish":
            res = r.republish(a.space_id)
            if res["published"]:
                print(f"republished epoch keys for epoch {res['epoch']}")
            else:
                print("space is at epoch 0 — nothing to publish")
        elif a.cmd == "rotate":
            res = r.rotate(a.space_id)
            if res["rotated"]:
                print(f"rotated to epoch {res['epoch']}")
            else:
                print(f"already at epoch {res['epoch']} — nothing to do")
        elif a.cmd == "rotate-key":
            res = r.rotate_key(a.space_id)
            print(f"new link: {res['link']}")
            print("forward-only: the old link can no longer join, but "
                  "existing members are NOT evicted (use kick for that), "
                  "and old v1 messages stay readable with the retained "
                  "keys.")
            if res["epoch"] == 0:
                print("WARNING: this space is still at epoch 0 (v1). "
                      "Link rotation fragments v1 messaging until the "
                      "space moves to v2 (epoch rotation via a kick "
                      "cycle): members holding only the old key cannot "
                      "read new v1 messages, and vice versa.")
        elif a.cmd == "rotate-epoch":
            res = r.rotate_epoch(a.space_id)
            print(f"rotated epoch to {res['epoch']} (no members removed)")
            if res["left_behind"]:
                print("left on v1 (no X25519 key — rejoin to rotate): "
                      + ", ".join(res["left_behind"]))
        elif a.cmd == "delete":
            r.delete(a.space_id)
            print("deleted")
    except (RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
