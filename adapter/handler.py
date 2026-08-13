"""Lambda entry point: Attribute alert -> CloudFlow webhook.

    Attribute alerting
        | POST + X-Attribute-Signature (HMAC)
        v
    this adapter (Lambda Function URL, AuthType NONE -- HMAC is the gate)
        | verify signature, reject replays
        | resolve credential locally, DISCARD the secret
        | dedupe on idempotency_key
        | inject the DoiT API token from Secrets Manager
        v
    CloudFlow webhook trigger

Why this exists rather than pointing Attribute straight at CloudFlow:

1. The DoiT API token can revoke production credentials. Here it lives in
   Secrets Manager; Attribute holds only an HMAC secret that can do nothing but
   talk to this endpoint.
2. CloudFlow's webhook has no HMAC and no replay protection.
3. A runaway agent emits many alerts. Dedupe must happen before the flow runs.
4. Live credentials never cross into the DoiT platform -- only derived identity.

Environment:
    CLOUDFLOW_WEBHOOK_URL        required
    DOIT_API_TOKEN_SECRET_ID     required -- Secrets Manager id/ARN
    ATTRIBUTE_SIGNING_SECRET_ID  required -- Secrets Manager id/ARN; JSON list or
                                 comma-separated to allow rotation
    QUARANTINE_POLICY_ARN        required
    IDEMPOTENCY_TABLE            optional -- DynamoDB table; dedupe is skipped
                                 with a warning if unset
    PROTECTED_IAM_USERS          optional -- comma-separated, never auto-contained
    SIGNATURE_TOLERANCE_SECONDS  optional -- default 300
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache

from adapter.policy import (
    assert_no_secret,
    build_cloudflow_payload,
    decide_tier,
)
from adapter.signature import DEFAULT_TOLERANCE_SECONDS, SignatureError, verify
from resolver.bedrock import UnresolvableCredential, redact, resolve_alert

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CLOUDFLOW_TIMEOUT_SECONDS = 15
IDEMPOTENCY_TTL_SECONDS = 6 * 60 * 60


class RejectedAlert(Exception):
    """Alert rejected with a specific HTTP status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# --- AWS glue (lazily imported so the pure units stay testable) --------------


@lru_cache(maxsize=8)
def _secret(secret_id: str) -> str:
    import boto3

    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_id)["SecretString"]


def _signing_secrets(secret_id: str) -> list[str]:
    raw = _secret(secret_id)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return [part.strip() for part in raw.split(",") if part.strip()]

    if isinstance(parsed, list):
        return [str(item) for item in parsed if item]
    if isinstance(parsed, dict):
        return [str(value) for value in parsed.values() if value]
    return [str(parsed)]


def _claim_idempotency_key(table_name: str, key: str) -> bool:
    """Reserve ``key``. False means it was already claimed, so drop the alert."""
    import boto3
    from botocore.exceptions import ClientError

    table = boto3.resource("dynamodb").Table(table_name)
    try:
        table.put_item(
            Item={
                "idempotency_key": key,
                "expires_at": int(time.time()) + IDEMPOTENCY_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(idempotency_key)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise
    return True


def _post_to_cloudflow(url: str, token: str, payload: dict[str, object]) -> int:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=CLOUDFLOW_TIMEOUT_SECONDS) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        # Body may carry a CloudFlow schema-mismatch explanation; it contains no
        # secrets of ours, and is the fastest way to diagnose sample-JSON drift.
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RejectedAlert(502, f"CloudFlow rejected the request ({exc.code}): {detail}")
    except urllib.error.URLError as exc:
        raise RejectedAlert(504, f"could not reach CloudFlow: {exc.reason}")


# --- request handling --------------------------------------------------------


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RejectedAlert(500, f"{name} is not configured")
    return value


def _protected_users() -> frozenset[str]:
    raw = os.environ.get("PROTECTED_IAM_USERS", "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _extract(event: dict[str, object]) -> tuple[bytes, dict[str, str]]:
    """Pull the raw body and lowercased headers from a Function URL event."""
    import base64

    body = event.get("body") or ""
    raw = (
        base64.b64decode(body)
        if event.get("isBase64Encoded")
        else str(body).encode("utf-8")
    )
    headers = {
        str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()
    }
    return raw, headers


def process(
    raw_body: bytes,
    headers: dict[str, str],
    *,
    now: int,
) -> tuple[int, dict[str, object]]:
    """Validate, resolve, and forward. Returns (status, response body)."""
    verify(
        raw_body,
        headers.get("x-attribute-signature"),
        _signing_secrets(_required_env("ATTRIBUTE_SIGNING_SECRET_ID")),
        now=now,
        tolerance_seconds=int(
            os.environ.get("SIGNATURE_TOLERANCE_SECONDS", DEFAULT_TOLERANCE_SECONDS)
        ),
    )

    try:
        alert = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise RejectedAlert(400, f"body is not valid JSON: {exc}")
    if not isinstance(alert, dict):
        raise RejectedAlert(400, "body must be a JSON object")

    for field in ("alert_id", "detected_at", "severity", "signal", "provider"):
        if not alert.get(field):
            raise RejectedAlert(400, f"missing required field {field!r}")

    quarantine_policy_arn = _required_env("QUARANTINE_POLICY_ARN")
    credential = alert.get("credential") if isinstance(alert.get("credential"), str) else None

    try:
        resolved = resolve_alert(alert, policy_arn=quarantine_policy_arn)
    except UnresolvableCredential as exc:
        # Redacted by construction: resolver errors never embed the credential.
        raise RejectedAlert(422, f"could not resolve credential: {exc}")

    decision = decide_tier(
        str(alert["signal"]),
        str(alert["severity"]),
        requested_action=(
            str(alert["requested_action"]) if alert.get("requested_action") else None
        ),
        resolved=resolved,
        protected_iam_users=_protected_users(),
    )

    hint = redact(credential) if credential else str(alert.get("key_hint", ""))
    payload = build_cloudflow_payload(
        alert,
        resolved,
        decision,
        quarantine_policy_arn=quarantine_policy_arn,
        key_hint=hint,
        forwarded_at=datetime.fromtimestamp(now, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    )
    assert_no_secret(payload, credential)

    logger.info(
        json.dumps(
            {
                "event": "alert_resolved",
                "alert_id": payload["alert_id"],
                "signal": payload["signal"],
                "tier": payload["tier"],
                "credential_kind": payload["credential_kind"],
                "iam_user_name": payload["iam_user_name"],
                "needs_external_lookup": payload["needs_external_lookup"],
                "rationale": payload["tier_rationale"],
            }
        )
    )

    table = os.environ.get("IDEMPOTENCY_TABLE")
    if table:
        if not _claim_idempotency_key(table, str(payload["idempotency_key"])):
            return 200, {
                "status": "duplicate",
                "idempotency_key": payload["idempotency_key"],
            }
    else:
        logger.warning(
            "IDEMPOTENCY_TABLE unset: duplicate alerts from a retry loop will "
            "each reach CloudFlow"
        )

    status = _post_to_cloudflow(
        _required_env("CLOUDFLOW_WEBHOOK_URL"),
        _secret(_required_env("DOIT_API_TOKEN_SECRET_ID")),
        payload,
    )
    return 202, {
        "status": "forwarded",
        "cloudflow_status": status,
        "alert_id": payload["alert_id"],
        "tier": payload["tier"],
        "idempotency_key": payload["idempotency_key"],
    }


def lambda_handler(event: dict[str, object], context: object | None = None) -> dict[str, object]:
    del context
    raw_body, headers = _extract(event)

    try:
        status, body = process(raw_body, headers, now=int(time.time()))
    except SignatureError as exc:
        # Do not echo the reason to the caller; log it for operators only.
        logger.warning(json.dumps({"event": "signature_rejected", "reason": str(exc)}))
        status, body = 401, {"status": "unauthorized"}
    except RejectedAlert as exc:
        logger.warning(
            json.dumps({"event": "alert_rejected", "status": exc.status, "reason": exc.message})
        )
        status, body = exc.status, {"status": "rejected", "reason": exc.message}

    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
