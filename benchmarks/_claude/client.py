"""Build the Anthropic client for a credit-funded run, and nothing else.

The key is read from ``ANTHROPIC_API_KEY`` and passed explicitly, so the SDK cannot fall
back to an ``ant auth`` profile or another credential. A run refuses to start when:

* ``ANTHROPIC_API_KEY`` is unset or empty;
* ``ANTHROPIC_AUTH_TOKEN`` is set (the SDK would send it as a second credential);
* ``ANTHROPIC_BASE_URL`` points anywhere but the Anthropic API (the key would leave);
* the installed ``anthropic`` SDK is older than 1.0.

The key is never logged, printed, or included in an exception message. Supply it per
command, e.g. ``ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits
-w)" python -m benchmarks.mcptox fresh --run ...``, never via a shell profile: an exported
key also overrides the Claude Code subscription login in every ``claude -p`` run.
"""

from __future__ import annotations

import os
from typing import Any

ANTHROPIC_API_URL = "https://api.anthropic.com"


class ClientConfigError(RuntimeError):
    """Raised when the environment is not safe or not sufficient for a paid run."""


def check_environment() -> str:
    """Validate the credential environment and return the key (never log the result).

    Raises:
        ClientConfigError: A condition in the module docstring is not met.
    """
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key.strip():
        raise ClientConfigError(
            "ANTHROPIC_API_KEY is not set. Supply it for this command only, e.g. "
            'ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" '
            "<command>"
        )
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        raise ClientConfigError(
            "ANTHROPIC_AUTH_TOKEN is set; unset it so the API key is the only credential sent"
        )
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip().rstrip("/")
    if base_url and base_url != ANTHROPIC_API_URL:
        raise ClientConfigError(
            "ANTHROPIC_BASE_URL points away from the Anthropic API; refusing to send the key there"
        )
    return key


def sdk_version() -> str:
    """The installed ``anthropic`` SDK version, or ``"not installed"``."""
    try:
        import anthropic
    except ImportError:
        return "not installed"
    return str(anthropic.__version__)


def make_client(*, max_retries: int = 4, timeout: float = 120.0) -> Any:
    """Return an ``anthropic.Anthropic`` client for a paid run.

    Raises:
        ClientConfigError: The environment check fails, or the SDK is missing or too old.
    """
    key = check_environment()
    try:
        import anthropic
    except ImportError as exc:
        raise ClientConfigError(
            "the anthropic SDK is not installed; install it into the bench venv: "
            "uv pip install --python .venv/bin/python 'anthropic>=1.13'"
        ) from exc
    major = int(str(anthropic.__version__).split(".", 1)[0])
    if major < 1:
        raise ClientConfigError(
            f"anthropic {anthropic.__version__} is too old for the 5.x models; need >= 1.13"
        )
    return anthropic.Anthropic(api_key=key, max_retries=max_retries, timeout=timeout)
