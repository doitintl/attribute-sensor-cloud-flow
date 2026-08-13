"""Resolve a Bedrock credential from the command line.

    python -m resolver.cli ABSK...
    python -m resolver.cli --stdin < key.txt

Reads from stdin or a prompt by default so live credentials stay out of shell
history. Output carries no secret material.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from resolver.bedrock import UnresolvableCredential, redact, resolve

DEFAULT_POLICY_ARN = "arn:aws:iam::123456789012:policy/AttributeQuarantineBedrock"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "credential",
        nargs="?",
        help="credential or Authorization header; omit to be prompted",
    )
    parser.add_argument(
        "--stdin", action="store_true", help="read the credential from stdin"
    )
    parser.add_argument(
        "--policy-arn",
        default=DEFAULT_POLICY_ARN,
        help="ARN of the pre-created quarantine policy",
    )
    args = parser.parse_args(argv)

    if args.stdin:
        credential = sys.stdin.read()
    elif args.credential:
        credential = args.credential
    else:
        credential = getpass.getpass("credential (not echoed): ")

    try:
        resolved = resolve(credential, policy_arn=args.policy_arn)
    except UnresolvableCredential as exc:
        print(f"unresolvable: {exc}", file=sys.stderr)
        return 1

    print(f"# input: {redact(credential.strip())}")
    print(json.dumps(resolved.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
