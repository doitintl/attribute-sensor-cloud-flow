"""HMAC verification for inbound Attribute alerts.

CloudFlow's webhook trigger authenticates with a bearer token only. That token
can revoke production credentials, so the adapter adds a second, independent
proof that the request really came from Attribute.

Scheme (Stripe-style), in the ``X-Attribute-Signature`` header::

    t=1755093723,v1=9f2b3c...

``v1`` is ``HMAC-SHA256(secret, f"{t}.{raw_body}")`` as lowercase hex. The
timestamp is inside the signed material, so a captured request cannot be
replayed with a fresh timestamp -- the signature would no longer match.

Multiple ``v1=`` values are accepted so the shared secret can be rotated without
downtime: sign with both during the overlap.
"""

from __future__ import annotations

import hashlib
import hmac
import re

__all__ = [
    "DEFAULT_TOLERANCE_SECONDS",
    "SignatureError",
    "sign",
    "verify",
]

#: Requests older (or further in the future) than this are rejected as replays.
DEFAULT_TOLERANCE_SECONDS = 300

_SIGNATURE_HEADER_RE = re.compile(r"(?P<key>[a-z0-9]+)=(?P<value>[^,\s]+)")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class SignatureError(ValueError):
    """The request could not be authenticated as coming from Attribute."""


def _signed_payload(timestamp: str, raw_body: bytes) -> bytes:
    return timestamp.encode("utf-8") + b"." + raw_body


def sign(raw_body: bytes, secret: str, timestamp: int) -> str:
    """Produce a header value for ``raw_body``. Used by tests and the simulator."""
    digest = hmac.new(
        secret.encode("utf-8"),
        _signed_payload(str(timestamp), raw_body),
        hashlib.sha256,
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def _parse(header: str) -> tuple[str, list[str]]:
    timestamp: str | None = None
    signatures: list[str] = []
    for match in _SIGNATURE_HEADER_RE.finditer(header):
        key, value = match.group("key"), match.group("value")
        if key == "t" and timestamp is None:
            timestamp = value
        elif key == "v1":
            signatures.append(value)

    if timestamp is None:
        raise SignatureError("signature header has no 't=' timestamp")
    if not signatures:
        raise SignatureError("signature header has no 'v1=' digest")
    return timestamp, signatures


def verify(
    raw_body: bytes,
    header: str | None,
    secrets: list[str],
    *,
    now: int,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
) -> None:
    """Verify the request signature, or raise :class:`SignatureError`.

    Args:
        raw_body: The exact bytes received. Re-serialising parsed JSON would
            change the signed material and fail verification.
        header: Value of ``X-Attribute-Signature``.
        secrets: Accepted shared secrets; more than one permits rotation.
        now: Current unix time, injected so this stays a pure function.
        tolerance_seconds: Replay window, in either direction.
    """
    if not header:
        raise SignatureError("missing X-Attribute-Signature header")
    if not secrets or not any(secrets):
        # Never fail open: an unconfigured secret must not mean "allow all".
        raise SignatureError("no signing secret configured")

    timestamp, signatures = _parse(header)

    try:
        sent_at = int(timestamp)
    except ValueError as exc:
        raise SignatureError(f"non-numeric timestamp {timestamp!r}") from exc

    drift = now - sent_at
    if abs(drift) > tolerance_seconds:
        raise SignatureError(
            f"timestamp outside the {tolerance_seconds}s tolerance "
            f"(drift {drift}s); possible replay or clock skew"
        )

    expected = [
        hmac.new(
            secret.encode("utf-8"),
            _signed_payload(timestamp, raw_body),
            hashlib.sha256,
        ).hexdigest()
        for secret in secrets
        if secret
    ]

    for candidate in signatures:
        if not _HEX_RE.match(candidate):
            continue
        # compare_digest on every candidate, no early exit, to avoid leaking
        # which secret or which signature matched via timing.
        if any(hmac.compare_digest(candidate, digest) for digest in expected):
            return

    raise SignatureError("signature mismatch")
