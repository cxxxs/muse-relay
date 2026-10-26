#!/usr/bin/env python3
"""Phase 1 offline unit tests — no server, no network.

Covers: roster-bound author display (incl. spoofed author), epoch
wrap/unwrap roundtrips for multiple members, kick signature verification
(valid / forged / unknown member / stale epoch), v1/v2 signature domain
separation, and encrypted-at-rest state roundtrip + plaintext migration.

Run: python3 tests/test_phase1.py   (needs the `cryptography` package)

Everything here uses freshly generated random keys. Nothing is printed
except PASS/FAIL lines — no keys, codes, or links ever appear in output.
"""
import json
import os
import secrets
import stat
import sys
import tempfile

# Isolate local state: relay.py computes its config dir from $HOME at
# import time, so point HOME at a scratch dir BEFORE importing it. This
# keeps the tests off the developer's real ~/.config/muse-relay.
_TMP = tempfile.mkdtemp(prefix="relay-phase1-test-")
os.environ["HOME"] = _TMP

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import relay  # noqa: E402


def _space_id():
    return relay.b64e(secrets.token_bytes(16))


def _ed_keypair():
    return relay.gen_member_keypair()


def _x_keypair():
    return relay.gen_member_x_keypair()


def test_roster_display():
    pub_a, _ = _ed_keypair()
    pub_b, _ = _ed_keypair()
    pub_unknown, _ = _ed_keypair()
    roster = {pub_a: ("Alice", True), pub_b: ("Bob", False)}
    # Verified roster entry wins over a spoofed envelope author.
    assert relay.resolve_author(pub_a, roster, "Mallory") == ("Alice", True)
    # Uncertified roster entry does NOT win: falls back, clearly marked.
    assert relay.resolve_author(pub_b, roster, "Bob") == (
        "[unverified name] Bob", False)
    # Unknown key: fallback, clearly marked.
    assert relay.resolve_author(pub_unknown, roster, "Eve") == (
        "[unverified name] Eve", False)
    # Unknown key, no envelope author at all.
    assert relay.resolve_author(pub_unknown, roster, None) == (
        "[unverified name]", False)


def test_epoch_wrap_roundtrip():
    space = _space_id()
    epoch = 3
    admin_pub, admin_priv = _x_keypair()
    epoch_key = secrets.token_bytes(32)
    members = [_x_keypair() for _ in range(3)]
    blobs = []
    for member_pub, member_priv in members:
        shared = relay.ecdh_shared(admin_priv, member_pub)
        wk = relay.epoch_wrapping_key(shared, space, epoch)
        blobs.append(relay.wrap_epoch_key(wk, epoch_key))
    # Every member unwraps their own copy with ECDH(member_priv, admin_pub).
    for (member_pub, member_priv), blob in zip(members, blobs):
        shared = relay.ecdh_shared(member_priv, admin_pub)
        wk = relay.epoch_wrapping_key(shared, space, epoch)
        assert relay.unwrap_epoch_key(wk, blob) == epoch_key
    # A member's wrapping key does not open another member's blob.
    shared_b = relay.ecdh_shared(members[1][1], admin_pub)
    wk_b = relay.epoch_wrapping_key(shared_b, space, epoch)
    try:
        relay.unwrap_epoch_key(wk_b, blobs[0])
    except Exception:
        pass
    else:
        raise AssertionError("wrong member unwrapped another member's blob")
    # The wrapping key is bound to the space AND the epoch.
    shared0 = relay.ecdh_shared(admin_priv, members[0][0])
    wk_epoch3 = relay.epoch_wrapping_key(shared0, space, 3)
    wk_epoch4 = relay.epoch_wrapping_key(shared0, space, 4)
    wk_space2 = relay.epoch_wrapping_key(shared0, _space_id(), 3)
    assert wk_epoch3 != wk_epoch4
    assert wk_epoch3 != wk_space2


def test_kick_signatures():
    seed, control_pub = relay.gen_control_keypair()
    other_seed, _ = relay.gen_control_keypair()
    space = _space_id()
    pub_a, _ = _ed_keypair()
    pub_b, _ = _ed_keypair()
    pub_unknown, _ = _ed_keypair()
    roster = [pub_a, pub_b]
    # Valid admin signature, epoch exactly current + 1: accepted.
    sig = relay.sign_kick(seed, space, pub_b, 1)
    relay.validate_kick_request(roster, control_pub, space, 0, pub_b, 1, sig)
    assert relay.verify_kick(control_pub, space, pub_b, 1, sig)
    # Forged signature (wrong control seed): rejected.
    forged = relay.sign_kick(other_seed, space, pub_b, 1)
    assert not relay.verify_kick(control_pub, space, pub_b, 1, forged)
    try:
        relay.validate_kick_request(roster, control_pub, space, 0, pub_b, 1,
                                    forged)
    except ValueError:
        pass
    else:
        raise AssertionError("forged kick accepted")
    # Unknown member: rejected even with a well-formed signature.
    sig_unknown = relay.sign_kick(seed, space, pub_unknown, 1)
    try:
        relay.validate_kick_request(roster, control_pub, space, 0,
                                    pub_unknown, 1, sig_unknown)
    except ValueError:
        pass
    else:
        raise AssertionError("kick of unknown member accepted")
    # Stale or skipping epochs: rejected (epoch must be current + 1).
    for bad_epoch in (0, 2, 5):
        bad_sig = relay.sign_kick(seed, space, pub_b, bad_epoch)
        try:
            relay.validate_kick_request(roster, control_pub, space, 0, pub_b,
                                        bad_epoch, bad_sig)
        except ValueError:
            pass
        else:
            raise AssertionError(f"kick with epoch {bad_epoch} accepted")
    # Wrong space: rejected.
    assert not relay.verify_kick(control_pub, _space_id(), pub_b, 1, sig)


def test_v1_v2_domain_separation():
    pub, priv = _ed_keypair()
    space = _space_id()
    nonce, ct = relay.b64e(secrets.token_bytes(12)), relay.b64e(
        secrets.token_bytes(48))
    # v1 signature verifies as v1 only.
    sig1 = relay.sign_message(priv, space, nonce, ct)
    assert relay.verify_message(pub, space, nonce, ct, sig1)
    assert not relay.verify_message_v2(pub, space, 1, nonce, ct, sig1)
    # v2 signature verifies as v2 only, and only for its own epoch.
    sig2 = relay.sign_message_v2(priv, space, 1, nonce, ct)
    assert relay.verify_message_v2(pub, space, 1, nonce, ct, sig2)
    assert not relay.verify_message(pub, space, nonce, ct, sig2)
    assert not relay.verify_message_v2(pub, space, 2, nonce, ct, sig2)
    assert not relay.verify_message_v2(pub, _space_id(), 1, nonce, ct, sig2)


def test_state_encryption():
    space = _space_id()
    pub, priv = _ed_keypair()
    x_pub, x_priv = _x_keypair()
    state = {
        "space_id": space, "key_b64": relay.b64e(secrets.token_bytes(32)),
        "code": "test words only, never a real code",
        "member": {"pub_b64": pub, "priv_b64": priv,
                   "x_pub_b64": x_pub, "x_priv_b64": x_priv},
        "display_name": "TestDisplayNameZZZ", "control_pub": pub,
        "control_seed": "test-seed-placeholder",
        "epoch": 2, "epoch_key_b64": relay.b64e(secrets.token_bytes(32)),
    }
    # Save -> load roundtrips exactly, and the file holds no plaintext.
    relay.save_space(state)
    path = relay._space_path(space)
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    wrapper = json.loads(raw)
    assert wrapper.get("v") == 2 and "nonce" in wrapper and "ct" in wrapper
    assert "TestDisplayNameZZZ" not in raw
    assert "test-seed-placeholder" not in raw
    assert relay.load_space(space) == state
    # The local key file exists, holds 32 bytes, and is owner-read-only.
    key_path = relay.LOCAL_KEY_FILE
    assert os.path.exists(key_path)
    assert len(open(key_path, "rb").read()) == 32
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o400
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    # Plaintext migration: write a v1 plaintext file, load it, and check
    # the backup, the encrypted rewrite, and the second load.
    space2 = _space_id()
    plain = dict(state, space_id=space2)
    path2 = relay._space_path(space2)
    os.makedirs(os.path.dirname(path2), exist_ok=True)
    with open(path2, "w", encoding="utf-8") as f:
        json.dump(plain, f)
    assert relay.load_space(space2) == plain
    with open(path2 + ".bak", encoding="utf-8") as f:
        assert json.load(f) == plain
    with open(path2, encoding="utf-8") as f:
        assert json.load(f).get("v") == 2
    assert relay.load_space(space2) == plain


def test_cli_rotate_does_not_delete():
    """Regression: rotate must never call delete (a dispatch bug once did)."""
    import relay as R
    calls = []
    class FakeRelay:
        def __init__(self, base): pass
        def rotate(self, sid): calls.append(("rotate", sid)); return {"epoch": 1, "rotated": True}
        def delete(self, sid): calls.append(("delete", sid))
    orig = R.Relay
    R.Relay = FakeRelay
    try:
        assert R.main(["--base", "https://example.invalid", "rotate", "SID123"]) == 0
        assert calls == [("rotate", "SID123")], calls
        calls.clear()
        assert R.main(["--base", "https://example.invalid", "delete", "SID123"]) == 0
        assert calls == [("delete", "SID123")], calls
    finally:
        R.Relay = orig
    print("PASS cli rotate/delete dispatch (rotate never deletes)")

def _fake_creator_state(space_id):
    import relay as R
    import secrets
    ctrl_seed, ctrl_pub = R.gen_control_keypair()
    pub, _priv = R.gen_member_keypair()
    x_pub, x_priv = R.gen_member_x_keypair()
    return {
        "space_id": space_id, "key_b64": R.b64e(secrets.token_bytes(32)),
        "control_seed": ctrl_seed, "control_pub": ctrl_pub,
        "member": {"pub_b64": pub, "x_pub_b64": x_pub, "x_priv_b64": x_priv},
        "epoch": 0,
    }


def _fake_member(name):
    import relay as R
    pub, _priv = R.gen_member_keypair()
    x_pub, x_priv = R.gen_member_x_keypair()
    return {"pubkey": pub, "display_name": name, "x_pubkey": x_pub,
            "_x_priv": x_priv}


def test_atomic_kick_single_post():
    """kick() must send removal + bundle in ONE /kick POST (never a
    separate /epoch-keys call), and the wrapped keys must unwrap for the
    remaining members."""
    import relay as R
    sid = R.b64e(b"0123456789abcdef")
    state = _fake_creator_state(sid)
    creator = {"pubkey": state["member"]["pub_b64"],
               "display_name": "creator",
               "x_pubkey": state["member"]["x_pub_b64"]}
    target = _fake_member("target")
    other = _fake_member("other")
    roster = [creator,
              {k: v for k, v in target.items() if not k.startswith("_")},
              {k: v for k, v in other.items() if not k.startswith("_")}]
    calls = []
    saved = {}

    class FakeRelay(R.Relay):
        def __init__(self, base): pass
        def members(self, sid2):
            return {"members": roster, "epoch": 0}
        def _req(self, method, path, body=None, params=None):
            calls.append((method, path, body))
            return {"ok": True, "epoch": 1}

    orig_load, orig_save = R.load_space, R.save_space
    R.load_space = lambda sid2: state
    R.save_space = lambda s: (saved.clear(), saved.update(s))
    try:
        res = FakeRelay("https://example.invalid").kick(sid, target["pubkey"])
    finally:
        R.load_space, R.save_space = orig_load, orig_save
    assert len(calls) == 1, calls
    method, path, body = calls[0]
    assert method == "POST" and path.endswith("/kick"), path
    assert body["pubkey"] == target["pubkey"] and body["epoch"] == 1
    assert body["admin_x_pub"] == state["member"]["x_pub_b64"]
    assert body["epoch_signature"] and body["signature"]
    wrapped_pubs = {k["pubkey"] for k in body["keys"]}
    assert wrapped_pubs == {creator["pubkey"], other["pubkey"]}, wrapped_pubs
    assert res["epoch"] == 1 and res["kicked"] == "target"
    assert saved.get("epoch") == 1 and saved.get("epoch_key_b64")
    assert "pending_epoch" not in saved
    # The other member can actually unwrap its entry.
    entry = next(k for k in body["keys"] if k["pubkey"] == other["pubkey"])
    shared = R.ecdh_shared(other["_x_priv"], state["member"]["x_pub_b64"])
    wk = R.epoch_wrapping_key(shared, sid, 1)
    assert R.unwrap_epoch_key(wk, entry["wrapped"]) == R.b64d(
        saved["epoch_key_b64"])
    print("PASS atomic kick single POST (bundle unwraps)")


def test_republish_heals_bundle():
    """republish() uploads a bundle for the current epoch and stores the
    key, healing a kicked-but-keyless space."""
    import relay as R
    sid = R.b64e(b"0123456789abcdef")
    state = _fake_creator_state(sid)
    creator = {"pubkey": state["member"]["pub_b64"],
               "display_name": "creator",
               "x_pubkey": state["member"]["x_pub_b64"]}
    other = _fake_member("other")
    roster = [creator,
              {k: v for k, v in other.items() if not k.startswith("_")}]
    calls = []
    saved = {}

    class FakeRelay(R.Relay):
        def __init__(self, base): pass
        def members(self, sid2):
            return {"members": roster, "epoch": 1}
        def _req(self, method, path, body=None, params=None):
            calls.append((method, path, body))
            return {"ok": True, "epoch": 1}

    orig_load, orig_save = R.load_space, R.save_space
    R.load_space = lambda sid2: state
    R.save_space = lambda s: (saved.clear(), saved.update(s))
    try:
        res = FakeRelay("https://example.invalid").republish(sid)
    finally:
        R.load_space, R.save_space = orig_load, orig_save
    assert res == {"epoch": 1, "published": True}, res
    assert len(calls) == 1 and calls[0][1].endswith("/epoch-keys")
    assert calls[0][2]["epoch"] == 1
    assert {k["pubkey"] for k in calls[0][2]["keys"]} == {
        creator["pubkey"], other["pubkey"]}
    assert saved.get("epoch") == 1 and saved.get("epoch_key_b64")
    print("PASS republish heals bundle")


def test_send_retries_stale_epoch():
    """A v2 send rejected as 'stale epoch' while the server view lags
    must retry the identical (deduped) POST instead of failing."""
    import relay as R
    import secrets
    sid = R.b64e(b"0123456789abcdef")
    pub, _priv = R.gen_member_keypair()
    state = {"space_id": sid, "key_b64": R.b64e(secrets.token_bytes(32)),
             "epoch": 1, "epoch_key_b64": R.b64e(secrets.token_bytes(32)),
             "display_name": "creator",
             "member": {"pub_b64": pub, "priv_b64": _priv}}
    posts = []

    class FakeRelay(R.Relay):
        def __init__(self, base): pass
        def members(self, sid2):
            return {"members": [], "epoch": 1}
        def _req(self, method, path, body=None, params=None):
            posts.append(body)
            if len(posts) == 1:
                raise RuntimeError("stale epoch — rotate first")
            return {"ok": True, "id": body["id"]}

    orig_load = R.load_space
    R.load_space = lambda sid2: state
    try:
        out = FakeRelay("https://example.invalid").send(sid, "hello")
    finally:
        R.load_space = orig_load
    assert out["ok"] is True
    assert len(posts) == 2 and posts[0]["id"] == posts[1]["id"]
    assert posts[0]["version"] == 2 and posts[0]["epoch"] == 1
    print("PASS send retries stale epoch (same id, no double-post)")


def test_rotate_uses_bundle_epoch():
    """rotate() must notice an advance the members read missed, via the
    independent bundle read."""
    import relay as R
    import secrets
    sid = R.b64e(b"0123456789abcdef")
    pub, _priv = R.gen_member_keypair()
    x_pub, x_priv = R.gen_member_x_keypair()
    admin_x_pub, _admin_x_priv = R.gen_member_x_keypair()
    epoch_key = secrets.token_bytes(32)
    shared = R.ecdh_shared(x_priv, admin_x_pub)
    wk = R.epoch_wrapping_key(shared, sid, 1)
    wrapped = R.wrap_epoch_key(wk, epoch_key)
    state = {"space_id": sid, "epoch": 0,
             "member": {"pub_b64": pub, "x_priv_b64": x_priv}}
    saved = {}

    class FakeRelay(R.Relay):
        def __init__(self, base): pass
        def members(self, sid2):
            # Stale read: epoch 0, but the roster still lists us.
            return {"members": [{"pubkey": pub}], "epoch": 0}
        def _req(self, method, path, body=None, params=None):
            return {"epoch": 1, "admin_x_pub": admin_x_pub,
                    "keys": [{"pubkey": pub, "wrapped": wrapped}]}

    orig_load, orig_save = R.load_space, R.save_space
    R.load_space = lambda sid2: state
    R.save_space = lambda s: (saved.clear(), saved.update(s))
    try:
        res = FakeRelay("https://example.invalid").rotate(sid)
    finally:
        R.load_space, R.save_space = orig_load, orig_save
    assert res == {"epoch": 1, "rotated": True}, res
    assert saved.get("epoch") == 1
    assert R.b64d(saved["epoch_key_b64"]) == epoch_key
    print("PASS rotate uses bundle epoch")


TESTS = [
    ("roster display (incl. spoofed author)", test_roster_display),
    ("epoch wrap/unwrap roundtrip (3 members)", test_epoch_wrap_roundtrip),
    ("kick signatures (valid/forged/unknown/stale)", test_kick_signatures),
    ("v1/v2 signature domain separation", test_v1_v2_domain_separation),
    ("state encryption roundtrip + migration", test_state_encryption),
    ("cli rotate/delete dispatch (rotate never deletes)", test_cli_rotate_does_not_delete),
    ("atomic kick single POST (bundle unwraps)", test_atomic_kick_single_post),
    ("republish heals bundle", test_republish_heals_bundle),
    ("send retries stale epoch (same id, no double-post)", test_send_retries_stale_epoch),
    ("rotate uses bundle epoch", test_rotate_uses_bundle_epoch),
]


def main() -> int:
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
        except Exception as e:
            failed += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
        else:
            print(f"PASS {name}")
    print(f"{len(TESTS) - failed}/{len(TESTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
