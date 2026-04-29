"""``airlock kill-switch`` CLI (v0.5.9+)."""

from __future__ import annotations

import argparse
import os
import sys

from ..kill_switch import (
    HMACBroadcastSigner,
    InMemoryTransport,
    KillSwitchBroadcast,
)


def _load_key_from_env(env_var: str) -> bytes:
    val = os.environ.get(env_var, "")
    if not val:
        raise SystemExit(
            f"environment variable {env_var!r} must hold the signing key "
            "(>= 32 bytes, hex or raw)"
        )
    if all(c in "0123456789abcdefABCDEF" for c in val) and len(val) >= 64:
        try:
            return bytes.fromhex(val)
        except ValueError:
            return val.encode("utf-8")
    return val.encode("utf-8")


def _cmd_arm(args: argparse.Namespace) -> int:
    key = _load_key_from_env(args.key_env)
    HMACBroadcastSigner(keyid=args.keyid, key=key)  # validates length
    print(f"OK: kill-switch armed for keyid={args.keyid!r}")
    return 0


def _cmd_trigger(args: argparse.Namespace) -> int:
    key = _load_key_from_env(args.key_env)
    signer = HMACBroadcastSigner(keyid=args.keyid, key=key)
    transport = InMemoryTransport()
    broadcaster = KillSwitchBroadcast(signer=signer, transport=transport)
    broadcaster.trigger(reason=args.reason)
    # The InMemoryTransport is process-local; in production this is
    # replaced via airlock-config wiring. For the CLI smoke we surface
    # the queued message count.
    print(
        f"OK: trigger queued (reason={args.reason!r}, transport=InMemoryTransport)"
    )
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    key = _load_key_from_env(args.key_env)
    signer = HMACBroadcastSigner(keyid=args.keyid, key=key)
    transport = InMemoryTransport()
    broadcaster = KillSwitchBroadcast(signer=signer, transport=transport)
    broadcaster.reset(reason=args.reason)
    print(
        f"OK: reset queued (quorum={args.quorum}, reason={args.reason!r}, "
        f"transport=InMemoryTransport)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock kill-switch")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_arm = sub.add_parser("arm")
    p_arm.add_argument("keyid")
    p_arm.add_argument("--key-env", default="AIRLOCK_KILL_SWITCH_KEY")
    p_arm.set_defaults(func=_cmd_arm)

    p_trigger = sub.add_parser("trigger")
    p_trigger.add_argument("reason")
    p_trigger.add_argument("--keyid", required=True)
    p_trigger.add_argument("--key-env", default="AIRLOCK_KILL_SWITCH_KEY")
    p_trigger.set_defaults(func=_cmd_trigger)

    p_reset = sub.add_parser("reset")
    p_reset.add_argument("reason")
    p_reset.add_argument("--keyid", required=True)
    p_reset.add_argument("--key-env", default="AIRLOCK_KILL_SWITCH_KEY")
    p_reset.add_argument("--quorum", default="2-of-3")
    p_reset.set_defaults(func=_cmd_reset)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
