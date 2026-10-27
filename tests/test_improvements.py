#!/usr/bin/env python3
"""Improvements-batch offline unit tests — no server, no network.

Covers the 2 -> 7 -> 1 -> 4 -> 5 -> 6 build:
- item 2: short pubkey fingerprints in display (CLI + fetch data)
- item 7: roster anti-rollback history, notices, and merge-safe saves
- item 1: second-channel control-pubkey fingerprint pinning on joins
- item 4: link-key rotation (client) + v1 decryption via key history
- item 5: kickless epoch rotation (client), v1 flagging, join hook
- item 6: keychain local-key backend (mocked subprocess) + fallback

Run: python3 tests/test_improvements.py   (needs the `cryptography` package)

Everything here uses freshly generated random keys. Nothing is printed
except PASS/FAIL lines — no keys, codes, or links ever appear in output.
Server-side behavior (rotate-key endpoint, v1 retirement, duplicate
names, rotate-epoch endpoint) is covered by tests/test_worker_local.mjs,
which runs the real worker code offline against an in-memory KV.
"""
import io
import json
import os
import secrets
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="relay-improvements-test-")
os.environ["HOME"] = _TMP
# Silence the auto-backend fallback warning for tests that only need the
# file backend; the keychain test sets the backend explicitly.
os.environ["MUSE_RELAY_KEY_BACKEND"] = "file"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import relay as R  # noqa: E402


def _space_id():
    return R.b64e(secrets.token_bytes(16))


def _ed_keypair():
    return R.gen_member_keypair()


def _x_keypair():
    return R.gen_member_x_keypair()


def _member(name, with_x=True):
    pub, _priv = _ed_keypair()
    x_pub, x_priv = _x_keypair()
    m = {"pubkey": pub, "display_name": name}
    if with_x:
        m["x_pubkey"] = x_pub
        m["_x_priv"] = x_priv
    return m


def _pub_member(m):
    return {k: v for k, v in m.items() if not k.startswith("_")}


def test_short_fp_display():
    pub_a, _ = _ed_keypair()
    pub_b, _ = _ed_keypair()
    assert R.short_fp(pub_a) == pub_a[:6]
    assert R.short_fp(pub_a) != R.short_fp(pub_b)
    assert R.display_with_fp("jojo", pub_a) == f"jojo · {pub_a[:6]}"
    # Same name, different keys: visibly different.
    assert (R.display_with_fp("jojo", pub_a)
            != R.display_with_fp("jojo", pub_b))


def test_roster_notices_pure():
    a = _member("Alice")
    b = _member("Bob")
    pa, pb = a["pubkey"], b["pubkey"]
    h1 = R.roster_hash([_pub_member(a)])
    h2 = R.roster_hash([_pub_member(a), _pub_member(b)])
    assert h1 != h2
    # First observation: silent, just recorded.
    notices, obs1 = R._roster_notices(None, 0, [_pub_member(a)], [])
    assert notices == []
    assert obs1["hash"] == h1
    hist = [{"epoch": 0, "hash": h1}]
    # Join (no epoch bump — joins never bump the epoch): plain notice
    # with the joined list, no warning.
    notices, obs2 = R._roster_notices(obs1, 0, [_pub_member(a), _pub_member(b)], hist)
    assert [n["type"] for n in notices] == ["roster_changed"]
    assert notices[0]["joined"] == [pb] and notices[0]["left"] == []
    hist.append({"epoch": 0, "hash": h2})
    # Kick-shaped change (member left + epoch bump): change notice only,
    # no vanished warning, no revert warning.
    notices, obs3 = R._roster_notices(obs2, 1, [_pub_member(a)], hist)
    assert [n["type"] for n in notices] == ["roster_changed"]
    assert notices[0]["left"] == [pb]
    hist.append({"epoch": 1, "hash": h1})
    # Epoch decrease: warning.
    notices, _ = R._roster_notices(obs3, 0, [_pub_member(a)], hist)
    assert any(n["type"] == "epoch_decreased" for n in notices)
    # Member vanished without an epoch increase: warning.
    notices, _ = R._roster_notices(obs2, 0, [_pub_member(a)], hist)
    assert any(n["type"] == "member_vanished" for n in notices)
    # Hand-crafted rollback: roster returns to a previously seen hash
    # while the epoch stays at/below the previous roster's epoch.
    notices, _ = R._roster_notices(obs3, 1,
                                   [_pub_member(a), _pub_member(b)], hist)
    assert any(n["type"] == "roster_reverted" for n in notices)


def test_members_persists_history_and_notices():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    a = _member("Alice")
    b = _member("Bob")
    cert_a = R.sign_member_cert(seed, sid, a["pubkey"], "Alice")
    cert_b = R.sign_member_cert(seed, sid, b["pubkey"], "Bob")
    roster1 = [{**_pub_member(a), "cert": cert_a}]
    roster2 = [{**_pub_member(a), "cert": cert_a},
               {**_pub_member(b), "cert": cert_b}]
    state = {"space_id": sid, "key_b64": R.b64e(secrets.token_bytes(32)),
             "control_pub": ctrl_pub, "epoch": 0,
             "member": {"pub_b64": a["pubkey"]}}
    R.save_space(state)

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base
            self.calls = 0

        def _req(self, method, path, body=None, params=None):
            self.calls += 1
            if self.calls == 1:
                return {"members": roster1, "epoch": 0}
            return {"members": roster2, "epoch": 0}

    r = FakeRelay("https://example.invalid")
    resp1 = r.members(sid)
    assert resp1["notices"] == []
    resp2 = r.members(sid)
    assert [n["type"] for n in resp2["notices"]] == ["roster_changed"]
    assert resp2["notices"][0]["joined"] == [b["pubkey"]]
    saved = R.load_space(sid)
    assert saved["roster_last"]["hash"] == R.roster_hash(roster2)
    assert len(saved["roster_history"]) == 2
    # The notice was recorded in the audit log (type field only checked).
    log_path = os.path.join(R.AUDIT_DIR, sid + ".log")
    with open(log_path, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f]
    assert any(line.get("type") == "roster-notice" for line in lines)


def test_join_pin():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    space_key = secrets.token_bytes(32)
    wrapped_control = R.wrap_control_seed(space_key, seed)

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base
            self.registered = False

        def _req(self, method, path, body=None, params=None):
            if method == "GET":
                return {"wrapped_control": wrapped_control,
                        "control_pub": ctrl_pub}
            self.registered = True
            return {"ok": True}

    link = f"https://example.invalid/s/{sid}#k={R.b64e(space_key)}"
    # No flag: joins fine.
    r = FakeRelay("https://example.invalid")
    s = r.join_link(link, "Tester")
    assert s["control_pub"] == ctrl_pub and r.registered
    # Matching short fingerprint and full pubkey both pass.
    r = FakeRelay("https://example.invalid")
    r.join_link(link, "Tester", R.short_fp(ctrl_pub))
    r = FakeRelay("https://example.invalid")
    r.join_link(link, "Tester", ctrl_pub)
    # Mismatch: refuses BEFORE registering.
    r = FakeRelay("https://example.invalid")
    try:
        r.join_link(link, "Tester", "000000")
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched fingerprint accepted")
    assert not r.registered


def test_join_code_pin_and_seed_chain():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    words = ["maple", "otter", "grove", "river", "stone", "cloud", "fern", "wren"]
    lookup = R.derive_lookup(words)
    kek = R.derive_kek(words, lookup)
    space_key = secrets.token_bytes(32)
    wrapped = R.wrap_space_key(kek, space_key)
    wrapped_control = R.wrap_control_seed(space_key, seed)

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base
            self.registered = False

        def _req(self, method, path, body=None, params=None):
            if path == "/api/spaces/join":
                return {"space_id": sid, "wrapped": wrapped,
                        "wrapped_control": wrapped_control,
                        "control_pub": ctrl_pub}
            self.registered = True
            return {"ok": True}

    r = FakeRelay("https://example.invalid")
    s = r.join_code(" ".join(words), "Tester")
    assert s["control_pub"] == ctrl_pub and r.registered
    # The code path also pins.
    r = FakeRelay("https://example.invalid")
    try:
        r.join_code(" ".join(words), "Tester", "000000")
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched fingerprint accepted (code)")


def test_rotate_key_client():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    old_key = secrets.token_bytes(32)
    words = ["maple", "otter", "grove", "river", "stone", "cloud", "fern", "wren"]
    state = {"space_id": sid, "key_b64": R.b64e(old_key),
             "code": " ".join(words), "control_seed": seed,
             "control_pub": ctrl_pub, "epoch": 1,
             "link": f"https://example.invalid/s/{sid}#k={R.b64e(old_key)}",
             "member": {"pub_b64": _ed_keypair()[0]}}
    calls = []

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base

        def _req(self, method, path, body=None, params=None):
            calls.append((method, path, body))
            return {"ok": True}

    orig_load, orig_save = R.load_space, R.save_space
    saved = {}
    R.load_space = lambda sid2: state
    R.save_space = lambda s: (saved.clear(), saved.update(s))
    try:
        res = FakeRelay("https://example.invalid").rotate_key(sid)
    finally:
        R.load_space, R.save_space = orig_load, orig_save
    assert len(calls) == 1
    method, path, body = calls[0]
    assert method == "POST" and path.endswith("/rotate-key"), path
    # The signature verifies against the control pubkey over both blobs.
    assert R.verify_rotate_key(ctrl_pub, sid, body["wrapped_control"],
                                body["wrapped"], body["signature"])
    assert saved["key_history_b64"] == [R.b64e(old_key)]
    assert saved["key_b64"] != R.b64e(old_key)
    assert res["link"] == saved["link"] and res["epoch"] == 1
    # No code, no rotation: the code-path blob could not be re-wrapped.
    state2 = dict(state)
    state2.pop("code")
    R.load_space = lambda sid2: state2
    try:
        FakeRelay("https://example.invalid").rotate_key(sid)
    except RuntimeError:
        pass
    else:
        raise AssertionError("rotate-key without code accepted")
    finally:
        R.load_space = orig_load


def test_control_seed_via_code():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    words = ["maple", "otter", "grove", "river", "stone", "cloud", "fern", "wren"]
    lookup = R.derive_lookup(words)
    kek = R.derive_kek(words, lookup)
    space_key = secrets.token_bytes(32)
    wrapped = R.wrap_space_key(kek, space_key)
    wrapped_control = R.wrap_control_seed(space_key, seed)
    state = {"space_id": sid, "code": " ".join(words)}

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base

        def _req(self, method, path, body=None, params=None):
            return {"space_id": sid, "wrapped": wrapped,
                    "wrapped_control": wrapped_control,
                    "control_pub": ctrl_pub}

    r = FakeRelay("https://example.invalid")
    assert r._control_seed_for(state, sid) == seed


def test_fetch_v1_key_history():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    old_key = secrets.token_bytes(32)
    new_key = secrets.token_bytes(32)
    sender_pub, sender_priv = _ed_keypair()
    own_pub, _own_priv = _ed_keypair()
    cert = R.sign_member_cert(seed, sid, sender_pub, "Sender")
    roster = [{"pubkey": sender_pub, "display_name": "Sender",
               "cert": cert, "x_pubkey": _x_keypair()[0]}]
    nonce, ct = R.encrypt_message(old_key, "Sender", "hello old")
    sig = R.sign_message(sender_priv, sid, nonce, ct)
    state = {"space_id": sid, "key_b64": R.b64e(new_key),
             "key_history_b64": [R.b64e(old_key)],
             "control_pub": ctrl_pub, "epoch": 0,
             "display_name": "Me",
             "member": {"pub_b64": own_pub}}

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base

        def _req(self, method, path, body=None, params=None):
            if path.endswith("/members"):
                return {"members": roster, "epoch": 0}
            return {"messages": [{"id": "000000000000001-aaa", "ts": 1,
                                  "nonce": nonce, "ciphertext": ct,
                                  "pubkey": sender_pub, "signature": sig,
                                  "version": 1}]}

    orig_load, orig_save = R.load_space, R.save_space
    R.load_space = lambda sid2: state
    R.save_space = lambda s: None
    try:
        out = FakeRelay("https://example.invalid").fetch(sid)
    finally:
        R.load_space, R.save_space = orig_load, orig_save
    assert len(out) == 1
    assert out[0]["body"] == "hello old" and out[0]["decrypt_ok"]
    assert out[0]["sig_ok"] and out[0]["author_display"] == "Sender"
    assert out[0]["author_fp"] == sender_pub[:6]


def test_rotate_epoch_client():
    sid = _space_id()
    seed, ctrl_pub = R.gen_control_keypair()
    creator_pub, _ = _ed_keypair()
    creator_x_pub, creator_x_priv = _x_keypair()
    other = _member("other")
    v1_member = _member("legacy", with_x=False)
    state = {"space_id": sid, "control_seed": seed, "control_pub": ctrl_pub,
             "epoch": 0, "member": {"pub_b64": creator_pub,
                                    "x_pub_b64": creator_x_pub,
                                    "x_priv_b64": creator_x_priv}}
    roster = [{"pubkey": creator_pub, "display_name": "creator",
               "x_pubkey": creator_x_pub},
              _pub_member(other),
              _pub_member(v1_member)]
    calls = []
    saved = {}

    class FakeRelay(R.Relay):
        def __init__(self, base):
            self.base = base

        def members(self, sid2):
            return {"members": roster, "epoch": 0, "notices": []}

        def _req(self, method, path, body=None, params=None):
            calls.append((method, path, body))
            return {"ok": True, "epoch": 1}

    orig_load, orig_save = R.load_space, R.save_space
    R.load_space = lambda sid2: state
    R.save_space = lambda s: (saved.clear(), saved.update(s))
    try:
        res = FakeRelay("https://example.invalid").rotate_epoch(sid)
    finally:
        R.load_space, R.save_space = orig_load, orig_save
    assert len(calls) == 1
    method, path, body = calls[0]
    assert method == "POST" and path.endswith("/rotate-epoch"), path
    assert body["epoch"] == 1
    assert R.verify_epoch_bundle(ctrl_pub, sid, 1, body["signature"])
    wrapped_pubs = {k["pubkey"] for k in body["keys"]}
    assert wrapped_pubs == {creator_pub, other["pubkey"]}, wrapped_pubs
    # The other member can unwrap its entry.
    entry = next(k for k in body["keys"]
                 if k["pubkey"] == other["pubkey"])
    shared = R.ecdh_shared(other["_x_priv"], creator_x_pub)
    wk = R.epoch_wrapping_key(shared, sid, 1)
    assert R.unwrap_epoch_key(wk, entry["wrapped"]) == R.b64d(
        saved["epoch_key_b64"])
    assert res["epoch"] == 1 and res["left_behind"] == ["legacy"]
    assert saved.get("epoch") == 1 and "pending_epoch" not in saved


def _reset_keychain_flags():
    R._KEYCHAIN_DEAD = False
    R._KEYCHAIN_PUT_OK = False
    R._KEYCHAIN_WARNED = False


def test_keychain_backends():
    import subprocess
    import sys as _sys
    key = secrets.token_bytes(32)
    encoded = R.b64e(key)
    orig_backend = os.environ.get("MUSE_RELAY_KEY_BACKEND")
    orig_run = subprocess.run

    class FakeOut:
        def __init__(self, returncode=0, stdout=""):
            self.returncode = returncode
            self.stdout = stdout

    def set_backend(value):
        if value is None:
            os.environ.pop("MUSE_RELAY_KEY_BACKEND", None)
        else:
            os.environ["MUSE_RELAY_KEY_BACKEND"] = value

    try:
        # Keychain hit: the file is never created (remove any file an
        # earlier test created first).
        _reset_keychain_flags()
        set_backend("auto")
        if os.path.exists(R.LOCAL_KEY_FILE):
            os.remove(R.LOCAL_KEY_FILE)
        calls = []

        def fake_hit(argv, **kw):
            calls.append(argv)
            return FakeOut(0, encoded)

        subprocess.run = fake_hit
        assert R._local_key() == key
        assert not os.path.exists(R.LOCAL_KEY_FILE)
        # File backend never spawns a subprocess.
        _reset_keychain_flags()
        set_backend("file")
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("file backend must not spawn subprocess"))
        k2 = R._local_key()
        assert len(k2) == 32 and os.path.exists(R.LOCAL_KEY_FILE)
        # Tool missing: falls back to the file, and a hung/missing tool
        # is tried only once per process.
        _reset_keychain_flags()
        set_backend("auto")
        calls = []

        def fake_missing(argv, **kw):
            calls.append(argv)
            raise FileNotFoundError("no such tool")

        subprocess.run = fake_missing
        assert R._local_key() == k2
        assert R._local_key() == k2
        assert len(calls) == 1, calls
        # macOS argv shape (platform branch, execution mocked).
        _reset_keychain_flags()
        set_backend("auto")
        seen = []

        def fake_mac(argv, **kw):
            seen.append(argv)
            return FakeOut(0, encoded)

        subprocess.run = fake_mac
        orig_platform = _sys.platform
        try:
            _sys.platform = "darwin"
            assert R._local_key() == key
        finally:
            _sys.platform = orig_platform
        assert seen and seen[0][0] == "security" and "-w" in seen[0]
    finally:
        subprocess.run = orig_run
        set_backend(orig_backend)
        _reset_keychain_flags()


def test_cli_members_fingerprint_and_v1():
    import relay as R2
    a = _member("Alice")
    b = _member("legacy", with_x=False)
    resp = {"members": [{**_pub_member(a), "cert_ok": True},
                        {**_pub_member(b), "cert_ok": True}],
            "epoch": 0,
            "notices": [{"level": "notice", "type": "roster_changed",
                         "detail": "roster changed: joined Bob"}]}

    class FakeRelay:
        def __init__(self, base):
            pass

        def members(self, sid):
            return resp

    orig = R2.Relay
    R2.Relay = FakeRelay
    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        assert R2.main(["--base", "https://example.invalid",
                        "members", "SID123"]) == 0
    finally:
        sys.stdout, sys.stderr = old_out, old_err
        R2.Relay = orig
    assert f"Alice · {a['pubkey'][:6]}" in out.getvalue()
    assert f"legacy · {b['pubkey'][:6]} [v1]" in out.getvalue()
    assert "roster changed" in err.getvalue()


def test_cli_fetch_v1_tag():
    import relay as R2

    class FakeRelay:
        def __init__(self, base):
            pass

        def fetch(self, sid, since=""):
            return [
                {"sig_ok": True, "decrypt_ok": True, "version": 1,
                 "author_display": "Alice", "pubkey": "A" * 43,
                 "body": "old hello"},
                {"sig_ok": True, "decrypt_ok": True, "version": 2,
                 "author_display": "Bob", "pubkey": "B" * 43,
                 "body": "new hello"},
            ]

    orig = R2.Relay
    R2.Relay = FakeRelay
    out = io.StringIO()
    old_out = sys.stdout
    sys.stdout = out
    try:
        assert R2.main(["--base", "https://example.invalid",
                        "fetch", "SID123"]) == 0
    finally:
        sys.stdout = old_out
        R2.Relay = orig
    assert "[✓ v1] Alice · AAAAAA: old hello" in out.getvalue()
    assert "[✓] Bob · BBBBBB: new hello" in out.getvalue()


def test_rotate_on_join_hook():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rotate_on_join",
        os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "tools", "rotate-on-join.py"))
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    sid = _space_id()
    a = _member("Alice")
    calls = []

    class FakeRelay:
        def __init__(self, base):
            pass

        def members(self, sid2):
            return {"members": [{**_pub_member(a), "cert_ok": True}],
                    "epoch": 0,
                    "notices": [{"level": "notice", "type": "roster_changed",
                                 "detail": "roster changed",
                                 "joined": [a["pubkey"]], "left": []}]}

        def rotate_epoch(self, sid2):
            calls.append(sid2)
            return {"epoch": 1, "left_behind": []}

    orig_relay, orig_load = hook.Relay, hook.load_space
    orig_base = os.environ.get("MUSE_RELAY_BASE")
    os.environ["MUSE_RELAY_BASE"] = "https://example.invalid"
    out = io.StringIO()
    old_out = sys.stdout
    sys.stdout = out
    try:
        # No control seed: quiet, no rotation.
        hook.Relay = FakeRelay
        hook.load_space = lambda sid2: {"space_id": sid2}
        assert hook.main([sid]) == 0
        assert calls == []
        # Seed holder + certified join: rotates.
        hook.load_space = lambda sid2: {"space_id": sid2,
                                        "control_seed": "seed"}
        assert hook.main([sid]) == 0
        assert calls == [sid]
        assert "rotated epoch to 1" in out.getvalue()
    finally:
        sys.stdout = old_out
        hook.Relay, hook.load_space = orig_relay, orig_load
        if orig_base is None:
            os.environ.pop("MUSE_RELAY_BASE", None)
        else:
            os.environ["MUSE_RELAY_BASE"] = orig_base


TESTS = [
    ("short fingerprint display", test_short_fp_display),
    ("roster notices (pure)", test_roster_notices_pure),
    ("members persists history + notices", test_members_persists_history_and_notices),
    ("join pin (link)", test_join_pin),
    ("join pin + seed chain (code)", test_join_code_pin_and_seed_chain),
    ("rotate-key client", test_rotate_key_client),
    ("control seed via code", test_control_seed_via_code),
    ("fetch v1 via key history", test_fetch_v1_key_history),
    ("rotate-epoch client", test_rotate_epoch_client),
    ("keychain backends", test_keychain_backends),
    ("cli members fingerprint + v1", test_cli_members_fingerprint_and_v1),
    ("cli fetch v1 tag", test_cli_fetch_v1_tag),
    ("rotate-on-join hook", test_rotate_on_join_hook),
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
