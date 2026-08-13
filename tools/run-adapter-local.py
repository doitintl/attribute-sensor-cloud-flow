#!/usr/bin/env python3
"""Run the enforcement adapter locally, with no AWS and no deploy.

Stubs Secrets Manager (reads from env) and DynamoDB (in-memory), so the full
request path -- signature verification, replay rejection, resolution, tier
policy, dedupe, payload construction -- runs on your machine.

    # echo mode (default): print what WOULD be sent to CloudFlow, send nothing
    ATTRIBUTE_SIGNING_SECRET=devsecret python3 tools/run-adapter-local.py

    # forward mode: actually POST to a real CloudFlow webhook
    ATTRIBUTE_SIGNING_SECRET=devsecret \
    DOIT_API_TOKEN=... \
    CLOUDFLOW_WEBHOOK_URL=https://... \
      python3 tools/run-adapter-local.py --forward

Then, in another terminal:

    ATTRIBUTE_SIGNING_SECRET=devsecret ./tools/simulate-alert.sh --adapter http://127.0.0.1:8080

Binds to 127.0.0.1 only. Development harness -- not a deployment target.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from adapter import handler  # noqa: E402
from adapter.signature import SignatureError  # noqa: E402

_CLAIMED: set[str] = set()
_FORWARDED: list[dict[str, object]] = []


def _install_stubs(*, forward: bool) -> None:
    """Replace the AWS/network seams with local equivalents."""

    def fake_secret(secret_id: str) -> str:
        # Map the two secret ids onto plain env vars for local runs.
        if secret_id == "local-signing":
            return os.environ.get("ATTRIBUTE_SIGNING_SECRET", "")
        if secret_id == "local-doit-token":
            return os.environ.get("DOIT_API_TOKEN", "")
        raise KeyError(secret_id)

    def fake_claim(table_name: str, key: str) -> bool:
        del table_name
        if key in _CLAIMED:
            return False
        _CLAIMED.add(key)
        return True

    real_post = handler._post_to_cloudflow

    def echo_post(url: str, token: str, payload: dict[str, object]) -> int:
        del token  # never printed
        _FORWARDED.append(payload)
        print("\n--- payload that would be POSTed to CloudFlow " + "-" * 24)
        print(f"    url: {url or '(unset)'}")
        print(json.dumps(payload, indent=2))
        print("-" * 68 + "\n")
        return 202

    handler._secret = fake_secret  # type: ignore[assignment]
    handler._claim_idempotency_key = fake_claim  # type: ignore[assignment]
    if not forward:
        handler._post_to_cloudflow = echo_post  # type: ignore[assignment]
    else:
        def logged_post(url: str, token: str, payload: dict[str, object]) -> int:
            _FORWARDED.append(payload)
            print(f"--> forwarding alert {payload.get('alert_id')} "
                  f"tier={payload.get('tier')} to CloudFlow")
            status = real_post(url, token, payload)
            print(f"<-- CloudFlow returned {status}")
            return status

        handler._post_to_cloudflow = logged_post  # type: ignore[assignment]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        headers = {k.lower(): v for k, v in self.headers.items()}

        try:
            status, body = handler.process(raw, headers, now=int(time.time()))
        except SignatureError as exc:
            status, body = 401, {"status": "unauthorized", "_local_reason": str(exc)}
        except handler.RejectedAlert as exc:
            status, body = exc.status, {"status": "rejected", "reason": exc.message}
        except Exception as exc:  # surface stack traces locally instead of a 500
            import traceback

            traceback.print_exc()
            status, body = 500, {"status": "error", "reason": repr(exc)}

        encoded = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"  {self.address_string()} {fmt % args}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--forward",
        action="store_true",
        help="really POST to CLOUDFLOW_WEBHOOK_URL instead of echoing",
    )
    args = parser.parse_args()

    if not os.environ.get("ATTRIBUTE_SIGNING_SECRET"):
        print("error: ATTRIBUTE_SIGNING_SECRET is not set", file=sys.stderr)
        return 1
    if args.forward and not (
        os.environ.get("DOIT_API_TOKEN") and os.environ.get("CLOUDFLOW_WEBHOOK_URL")
    ):
        print(
            "error: --forward needs DOIT_API_TOKEN and CLOUDFLOW_WEBHOOK_URL",
            file=sys.stderr,
        )
        return 1

    os.environ.setdefault("ATTRIBUTE_SIGNING_SECRET_ID", "local-signing")
    os.environ.setdefault("DOIT_API_TOKEN_SECRET_ID", "local-doit-token")
    os.environ.setdefault("CLOUDFLOW_WEBHOOK_URL", "http://echo.local/unset")
    os.environ.setdefault(
        "QUARANTINE_POLICY_ARN",
        "arn:aws:iam::123456789012:policy/AttributeQuarantineBedrock",
    )
    os.environ.setdefault("IDEMPOTENCY_TABLE", "local-memory")

    _install_stubs(forward=args.forward)

    mode = "FORWARD to CloudFlow" if args.forward else "ECHO (nothing is sent)"
    print(f"adapter listening on http://127.0.0.1:{args.port}  [{mode}]")
    print(f"protected users: {os.environ.get('PROTECTED_IAM_USERS', '(none)')}")
    print("ctrl-c to stop\n")

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\nstopped. {len(_FORWARDED)} alert(s) processed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
