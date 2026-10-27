#!/usr/bin/env python3
"""Creator-side join-triggered epoch rotation (opt-in hook, NOT scheduled
by the relay itself).

Polls one space's roster via Relay.members(). The members() call already
records roster history and raises structured notices (see relay.py
_roster_notices). When a notice reports a newly joined member whose
certificate verifies, and this device holds the control seed (i.e. it is
a creator/seed-holder device), advance the epoch with rotate_epoch() so
the new member's arrival shrinks the current epoch's blast radius
instead of extending it.

Creator-side ONLY: a device without the control seed cannot rotate and
this script exits quietly for it (rotation is a seed-holder operation,
not a member operation). Run it from a scheduler on the creator device,
or call it from an existing poll loop. It prints one line per action
and nothing when there is nothing to do. It never prints keys, codes,
or links — only display names, fingerprints, and epochs.

Usage:
    MUSE_RELAY_BASE=<worker-url> python3 tools/rotate-on-join.py <space-id>
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from relay import Relay, load_space, short_fp  # noqa: E402


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("usage: rotate-on-join.py <space-id>", file=sys.stderr)
        return 2
    base = os.environ.get("MUSE_RELAY_BASE", "")
    if not base:
        print("error: set MUSE_RELAY_BASE", file=sys.stderr)
        return 2
    space_id = argv[0]
    try:
        state = load_space(space_id)
    except Exception as e:
        print(f"error: cannot load local state: {e}", file=sys.stderr)
        return 1
    if not state.get("control_seed"):
        # Not a creator/seed-holder device: rotation is not ours to do.
        # Quiet by design — this hook runs on every member's poll loop.
        return 0
    r = Relay(base)
    try:
        resp = r.members(space_id)
    except Exception as e:
        print(f"error: roster read failed: {e}", file=sys.stderr)
        return 1
    certified = {m["pubkey"] for m in resp["members"] if m.get("cert_ok")}
    joined = set()
    for n in resp.get("notices", []):
        if n.get("type") == "roster_changed":
            joined.update(p for p in n.get("joined", []) if p in certified)
    if not joined:
        return 0
    names = ", ".join(
        f"{next(m['display_name'] for m in resp['members'] if m['pubkey'] == p)} · {short_fp(p)}"
        for p in sorted(joined))
    print(f"new certified member(s): {names} — rotating epoch")
    try:
        res = r.rotate_epoch(space_id)
    except Exception as e:
        print(f"error: rotate-epoch failed: {e}", file=sys.stderr)
        return 1
    print(f"rotated epoch to {res['epoch']}")
    if res.get("left_behind"):
        print("left on v1 (no X25519 key — rejoin to rotate): "
              + ", ".join(res["left_behind"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
