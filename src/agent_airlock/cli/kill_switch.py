"""``airlock kill-switch`` CLI (v0.5.9+; made operational in v0.8.86).

What changed in v0.8.86
-----------------------
Through v0.8.85 every subcommand built a fresh :class:`InMemoryTransport`, published into
it, printed ``OK``, and exited — so the broadcast was discarded with the process and the
command reported success for an operation that reached nothing. ``--quorum`` was echoed
back without being parsed (``--quorum 9-of-9`` was accepted), and ``arm`` printed ``OK``
after only checking the key length.

Now a transport is required for anything that publishes: pass ``--redis-url`` or set
``AIRLOCK_KILL_SWITCH_REDIS_URL``. Without one the command **fails** rather than pretending,
because a kill switch that reports success while doing nothing is worse than one that is
obviously not configured.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Any

from ..kill_switch import (
    HMACBroadcastSigner,
    KillSwitchBroadcast,
    KillSwitchListener,
)

#: ``2-of-3``. Parsed so an impossible quorum is rejected instead of echoed.
_QUORUM_RE = re.compile(r"^(\d+)-of-(\d+)$")


def _load_key_from_env(env_var: str) -> bytes:
    val = os.environ.get(env_var, "")
    if not val:
        raise SystemExit(
            f"environment variable {env_var!r} must hold the signing key (>= 32 bytes, hex or raw)"
        )
    if all(c in "0123456789abcdefABCDEF" for c in val) and len(val) >= 64:
        try:
            return bytes.fromhex(val)
        except ValueError:
            return val.encode("utf-8")
    return val.encode("utf-8")


def _parse_quorum(text: str) -> tuple[int, int]:
    """Parse ``M-of-N``, rejecting an impossible quorum.

    Raises:
        SystemExit: If the value is malformed or M exceeds N.
    """
    match = _QUORUM_RE.match(text.strip())
    if not match:
        raise SystemExit(f"--quorum must look like '2-of-3', got {text!r}")
    threshold, total = int(match.group(1)), int(match.group(2))
    if threshold < 1:
        raise SystemExit(f"--quorum threshold must be at least 1, got {threshold}")
    if threshold > total:
        raise SystemExit(f"--quorum {text!r} is impossible: {threshold} of only {total} keys")
    return threshold, total


def _build_transport(args: argparse.Namespace) -> Any:
    """Build the configured transport, or exit explaining that there is none.

    A publish with no transport used to print ``OK`` and reach nothing. Refusing is the
    only honest option: the operator needs to know the fleet was not signalled.
    """
    url = getattr(args, "redis_url", None) or os.environ.get("AIRLOCK_KILL_SWITCH_REDIS_URL", "")
    if not url:
        raise SystemExit(
            "no broadcast transport configured — this command would reach no process.\n"
            "  Pass --redis-url redis://host:6379/0, or set "
            "AIRLOCK_KILL_SWITCH_REDIS_URL.\n"
            '  Requires the redis extra: pip install "agent-airlock[redis]"'
        )
    from ..kill_switch.transports.redis_stream import RedisStreamTransport

    try:
        return RedisStreamTransport.from_url(url, stream_key=args.stream_key)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


def _cmd_arm(args: argparse.Namespace) -> int:
    """Validate key material and report the fleet's current state.

    Arming is a *process* action — a worker calls
    ``agent_airlock.kill_switch.registry.install(listener)``. There is no remote arm, and
    this command no longer implies one.
    """
    key = _load_key_from_env(args.key_env)
    signer = HMACBroadcastSigner(keyid=args.keyid, key=key)
    print(f"OK: signing key for keyid={args.keyid!r} is valid ({len(key)} bytes).")
    if not (getattr(args, "redis_url", None) or os.environ.get("AIRLOCK_KILL_SWITCH_REDIS_URL")):
        print(
            "note: no transport configured, so fleet state was not read. Workers arm "
            "themselves by calling kill_switch.registry.install(listener)."
        )
        return 0
    listener = KillSwitchListener(
        signers=(signer,), transport=_build_transport(args), poll_interval_seconds=0
    )
    listener.poll()
    print(f"fleet state: {listener.state.value} (last reason: {listener.last_reason or '-'})")
    return 0


def _cmd_trigger(args: argparse.Namespace) -> int:
    key = _load_key_from_env(args.key_env)
    signer = HMACBroadcastSigner(keyid=args.keyid, key=key)
    transport = _build_transport(args)
    KillSwitchBroadcast(signer=signer, transport=transport).trigger(reason=args.reason)
    print(f"OK: trigger published to {args.stream_key!r} (reason={args.reason!r}).")
    print("Every process polling this stream freezes within its poll interval.")
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    key = _load_key_from_env(args.key_env)
    signer = HMACBroadcastSigner(keyid=args.keyid, key=key)
    threshold, total = _parse_quorum(args.quorum)
    transport = _build_transport(args)
    KillSwitchBroadcast(signer=signer, transport=transport).reset(reason=args.reason)
    print(f"OK: reset vote from keyid={args.keyid!r} published to {args.stream_key!r}.")
    print(
        f"This is 1 vote. Listeners configured {threshold}-of-{total} need "
        f"{threshold} distinct keyids before they disarm."
    )
    if (threshold, total) != (2, 3):
        print(
            "note: --quorum does not travel in the broadcast — the threshold is listener "
            "configuration (KillSwitchListener.reset_quorum_threshold). This value is "
            "used only to tell you how many more votes are needed."
        )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    """Read the fleet's current kill-switch state from the transport."""
    key = _load_key_from_env(args.key_env)
    signer = HMACBroadcastSigner(keyid=args.keyid, key=key)
    listener = KillSwitchListener(
        signers=(signer,), transport=_build_transport(args), poll_interval_seconds=0
    )
    listener.poll()
    votes, needed = listener.quorum_progress()
    print(f"state       : {listener.state.value}")
    print(f"last reason : {listener.last_reason or '-'}")
    print(f"reset votes : {votes}/{needed}")
    return 1 if listener.is_frozen() else 0


def _add_transport_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--redis-url",
        default=None,
        help="Redis URL for the broadcast stream (or $AIRLOCK_KILL_SWITCH_REDIS_URL)",
    )
    parser.add_argument(
        "--stream-key",
        default="airlock:killswitch",
        help="Redis stream key (default: %(default)s)",
    )
    parser.add_argument("--key-env", default="AIRLOCK_KILL_SWITCH_KEY")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock kill-switch")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_arm = sub.add_parser("arm", help="validate key material and read fleet state")
    p_arm.add_argument("keyid")
    _add_transport_args(p_arm)
    p_arm.set_defaults(func=_cmd_arm)

    p_trigger = sub.add_parser("trigger", help="freeze every process polling the stream")
    p_trigger.add_argument("reason")
    p_trigger.add_argument("--keyid", required=True)
    _add_transport_args(p_trigger)
    p_trigger.set_defaults(func=_cmd_trigger)

    p_reset = sub.add_parser("reset", help="publish one reset vote")
    p_reset.add_argument("reason")
    p_reset.add_argument("--keyid", required=True)
    p_reset.add_argument("--quorum", default="2-of-3")
    _add_transport_args(p_reset)
    p_reset.set_defaults(func=_cmd_reset)

    p_status = sub.add_parser("status", help="read the fleet's current state")
    p_status.add_argument("--keyid", required=True)
    _add_transport_args(p_status)
    p_status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
