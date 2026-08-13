"""Resolve an observed Amazon Bedrock credential to a containable IAM identity.

Attribute's sensor reports a credential as it appeared in outbound traffic. The
IAM APIs that stop that credential need internal identifiers instead. This
module bridges the two, for the three credential shapes that reach Bedrock:

1. Long-term Bedrock API key -- ``ABSK`` + base64. The base64 payload decodes to
   ``<ServiceUserName>:<secret>``, and the ServiceUserName embeds the IAM user
   name and the account ID::

       BedrockAPIKey-abcd+1-at-123456789012
       |___ iam user ___|++|___ account ___|
                        `- optional key index (secondary key)

   So the credential identifies its own owner -- no fingerprint registry needed.

2. SigV4-signed request -- the ``Authorization`` header carries the access key ID
   in cleartext inside ``Credential=<AKID>/<date>/<region>/<service>/aws4_request``.

3. Service-specific credential ID (``ACCA...``) -- already the identifier the IAM
   mutation APIs want; passed straight through.

The resolver never returns, logs, or stores the secret half of a credential.

Stdlib only, so this runs unchanged inside a CloudFlow Code node.

Verified against AWS documentation for the IAM/Bedrock APIs. The ``ABSK`` key
layout follows Wiz's published teardown
(https://www.wiz.io/blog/a-new-type-of-long-lived-key-on-aws-bedrock-api-keys);
assertions that depend on it are marked ``UNVERIFIED_AGAINST_REAL_KEY`` in the
test suite and should be confirmed against a throwaway key on a sandbox account.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "BEDROCK_SIGNING_SERVICES",
    "CredentialKind",
    "ContainmentAction",
    "LookupStep",
    "ResolvedCredential",
    "UnresolvableCredential",
    "redact",
    "resolve",
    "resolve_alert",
]


# --- constants ---------------------------------------------------------------

BEDROCK_API_KEY_PREFIX = "ABSK"

#: IAM's service name for Bedrock service-specific credentials.
BEDROCK_IAM_SERVICE_NAME = "bedrock.amazonaws.com"

#: SigV4 credential-scope service names that indicate Bedrock traffic. Both
#: endpoints must be contained -- denying only ``bedrock`` leaves Mantle open.
BEDROCK_SIGNING_SERVICES = frozenset({"bedrock", "bedrock-mantle"})

#: Actions a quarantine policy must deny to fully stop bearer-token calls.
BEARER_TOKEN_ACTIONS = (
    "bedrock:CallWithBearerToken",
    "bedrock-mantle:CallWithBearerToken",
)

_LONG_TERM_AKID_PREFIX = "AKIA"
_TEMPORARY_AKID_PREFIX = "ASIA"
_SERVICE_SPECIFIC_CRED_PREFIX = "ACCA"

# ``<stem>-at-<12-digit account>``. Anchored at the end because the stem may
# itself contain "-at-".
_ACCOUNT_SUFFIX_RE = re.compile(r"^(?P<stem>.+)-at-(?P<account>\d{12})$")

# Trailing ``+<n>`` marks a secondary key. IAM user names may legitimately
# contain "+", so the index is only split off when it is "+" plus digits.
_KEY_INDEX_RE = re.compile(r"^(?P<user>.+)\+(?P<index>\d+)$")

_SIGV4_CREDENTIAL_RE = re.compile(
    r"Credential=(?P<akid>[A-Z0-9]{16,128})"
    r"/(?P<date>\d{8})"
    r"/(?P<region>[a-z0-9-]+)"
    r"/(?P<service>[a-z0-9-]+)"
    r"/aws4_request"
)

_AKID_RE = re.compile(r"^[A-Z0-9]{16,128}$")


class CredentialKind(str, Enum):
    """What sort of credential was observed."""

    BEDROCK_LONG_TERM_API_KEY = "bedrock_long_term_api_key"
    IAM_ACCESS_KEY = "iam_access_key"
    IAM_TEMPORARY_CREDENTIAL = "iam_temporary_credential"
    SERVICE_SPECIFIC_CREDENTIAL_ID = "service_specific_credential_id"
    UNKNOWN = "unknown"


class UnresolvableCredential(ValueError):
    """The observed value is not a recognisable Bedrock credential."""


# --- output types ------------------------------------------------------------


@dataclass(frozen=True)
class LookupStep:
    """A read-only AWS call the flow must make before it can contain the key.

    Present when the observed credential does not carry enough information on
    its own. ``select`` documents how to pick the right record from the result.
    """

    api: str
    params: dict[str, str]
    select: str
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "api": self.api,
            "params": dict(self.params),
            "select": self.select,
            "note": self.note,
        }


@dataclass(frozen=True)
class ContainmentAction:
    """One AWS call that reduces or removes the credential's ability to spend.

    ``params`` values of the form ``${lookup.Field}`` must be filled from the
    corresponding :class:`LookupStep` result before the call is made.
    """

    api: str
    params: dict[str, object]
    tier: int
    reversible: bool
    undo: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "api": self.api,
            "params": dict(self.params),
            "tier": self.tier,
            "reversible": self.reversible,
            "undo": self.undo,
            "note": self.note,
        }


@dataclass(frozen=True)
class ResolvedCredential:
    """Identity behind an observed credential, plus how to contain it.

    Carries no secret material. ``lookups`` being non-empty means the flow needs
    an extra read call (or the CloudTrail fallback) before it can act.
    """

    kind: CredentialKind
    account_id: str | None = None
    iam_user_name: str | None = None
    service_user_name: str | None = None
    key_index: int | None = None
    access_key_id: str | None = None
    service_specific_credential_id: str | None = None
    region: str | None = None
    signing_service: str | None = None
    lookups: tuple[LookupStep, ...] = ()
    actions: tuple[ContainmentAction, ...] = ()
    warnings: tuple[str, ...] = field(default=())

    @property
    def is_actionable(self) -> bool:
        """True when at least one containment action is available."""
        return bool(self.actions)

    @property
    def needs_external_lookup(self) -> bool:
        """True when identity resolution is incomplete without an AWS read."""
        return bool(self.lookups)

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable form, for handing to downstream CloudFlow nodes."""
        return {
            "kind": self.kind.value,
            "account_id": self.account_id,
            "iam_user_name": self.iam_user_name,
            "service_user_name": self.service_user_name,
            "key_index": self.key_index,
            "access_key_id": self.access_key_id,
            "service_specific_credential_id": self.service_specific_credential_id,
            "region": self.region,
            "signing_service": self.signing_service,
            "lookups": [lookup.to_dict() for lookup in self.lookups],
            "actions": [action.to_dict() for action in self.actions],
            "warnings": list(self.warnings),
            "is_actionable": self.is_actionable,
            "needs_external_lookup": self.needs_external_lookup,
        }


# --- helpers -----------------------------------------------------------------


def redact(credential: str, keep: int = 4) -> str:
    """Render a credential safe for logs, keeping only a short prefix hint.

    Deliberately drops the tail as well as the middle: for an ``ABSK`` key the
    trailing bytes are the secret, and for SigV4 the tail is the signature.
    """
    if not credential:
        return ""
    head = credential[: max(keep, 0)]
    return f"{head}...[redacted:{len(credential)}]"


#: URL-safe base64 maps onto the standard alphabet, letting a single strict
#: decode handle both. Needed because ``urlsafe_b64decode`` takes no
#: ``validate`` argument, and the permissive decoder silently *discards*
#: ``-``/``_`` -- which would corrupt a user name rather than fail loudly.
_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


def _b64decode_strict(payload: str) -> bytes:
    """Decode base64, tolerating missing padding and the URL-safe alphabet."""
    normalised = payload.translate(_URLSAFE_TO_STANDARD)
    padded = normalised + "=" * (-len(normalised) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise UnresolvableCredential(
            "payload after ABSK prefix is not valid base64"
        ) from exc


def _split_service_user_name(
    service_user_name: str,
) -> tuple[str | None, int | None, str | None, list[str]]:
    """Split a ServiceUserName into (iam_user, key_index, account_id, warnings)."""
    warnings: list[str] = []

    account_match = _ACCOUNT_SUFFIX_RE.match(service_user_name)
    if account_match is None:
        warnings.append(
            "ServiceUserName has no '-at-<account-id>' suffix; account ID unknown "
            "and the IAM user name is a best-effort read of the whole string"
        )
        stem, account_id = service_user_name, None
    else:
        stem = account_match.group("stem")
        account_id = account_match.group("account")

    index_match = _KEY_INDEX_RE.match(stem)
    if index_match is None:
        iam_user_name, key_index = stem, None
    else:
        iam_user_name = index_match.group("user")
        key_index = int(index_match.group("index"))
        warnings.append(
            f"trailing '+{key_index}' read as a key index, so the IAM user is "
            f"{iam_user_name!r}; IAM user names may contain '+', so confirm "
            "against the ListServiceSpecificCredentials result"
        )

    if not iam_user_name:
        warnings.append("could not extract an IAM user name from ServiceUserName")
        return None, key_index, account_id, warnings

    return iam_user_name, key_index, account_id, warnings


def _quarantine_policy_action(
    *,
    target_kind: str,
    target_name: str,
    policy_arn: str,
) -> ContainmentAction:
    """Attach the pre-created quarantine policy to a user or role.

    Attaching a managed policy is one idempotent call, trivially undone, and
    leaves a clean audit record -- preferable to composing inline JSON per
    incident. It is also the only lever for temporary credentials.
    """
    api = "iam:AttachUserPolicy" if target_kind == "user" else "iam:AttachRolePolicy"
    undo = "iam:DetachUserPolicy" if target_kind == "user" else "iam:DetachRolePolicy"
    key = "UserName" if target_kind == "user" else "RoleName"
    return ContainmentAction(
        api=api,
        params={key: target_name, "PolicyArn": policy_arn},
        tier=2,
        reversible=True,
        undo=undo,
        note=(
            "Policy must deny both "
            f"{' and '.join(BEARER_TOKEN_ACTIONS)}; denying only the first "
            "leaves the Mantle endpoint able to spend."
        ),
    )


# --- resolvers ---------------------------------------------------------------


def _resolve_bedrock_api_key(credential: str, *, policy_arn: str) -> ResolvedCredential:
    payload = credential[len(BEDROCK_API_KEY_PREFIX) :]
    if not payload:
        raise UnresolvableCredential("ABSK prefix with no payload")

    raw = _b64decode_strict(payload)
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnresolvableCredential(
            "decoded ABSK payload is not UTF-8; value may be truncated or redacted"
        ) from exc

    service_user_name, separator, secret = decoded.partition(":")
    del secret  # never retained, returned, or logged

    if not separator:
        raise UnresolvableCredential(
            "decoded ABSK payload has no ':' separating ServiceUserName from secret"
        )
    if not service_user_name:
        raise UnresolvableCredential("decoded ABSK payload has an empty ServiceUserName")

    iam_user_name, key_index, account_id, warnings = _split_service_user_name(
        service_user_name
    )

    lookups: tuple[LookupStep, ...] = ()
    actions: list[ContainmentAction] = []

    if iam_user_name:
        lookups = (
            LookupStep(
                api="iam:ListServiceSpecificCredentials",
                params={
                    "UserName": iam_user_name,
                    "ServiceName": BEDROCK_IAM_SERVICE_NAME,
                },
                select=(
                    "ServiceSpecificCredentials[?ServiceUserName=="
                    f"'{service_user_name}'].ServiceSpecificCredentialId | [0]"
                ),
                note=(
                    "Match on the full ServiceUserName rather than the parsed IAM "
                    "user name -- a user may hold a primary and a secondary key."
                ),
            ),
        )
        actions.append(
            ContainmentAction(
                api="iam:UpdateServiceSpecificCredential",
                params={
                    "ServiceSpecificCredentialId": "${lookup.ServiceSpecificCredentialId}",
                    "Status": "Inactive",
                },
                tier=2,
                reversible=True,
                undo="iam:UpdateServiceSpecificCredential(Status=Active)",
                note=(
                    "Primary containment. IAM is eventually consistent, so "
                    "re-list and assert Status==Inactive before recording the "
                    "incident as contained."
                ),
            )
        )
        actions.append(
            _quarantine_policy_action(
                target_kind="user",
                target_name=iam_user_name,
                policy_arn=policy_arn,
            )
        )
        actions.append(
            ContainmentAction(
                api="iam:DeleteServiceSpecificCredential",
                params={
                    "ServiceSpecificCredentialId": "${lookup.ServiceSpecificCredentialId}"
                },
                tier=3,
                reversible=False,
                undo=None,
                note=(
                    "Irreversible; gate behind approval. Deleting the key does "
                    "not delete the auto-created IAM user -- clean that up "
                    "separately."
                ),
            )
        )
    else:
        warnings.append(
            "no IAM user name available, so no containment action can be built; "
            "fall back to CloudTrail identity resolution"
        )

    return ResolvedCredential(
        kind=CredentialKind.BEDROCK_LONG_TERM_API_KEY,
        account_id=account_id,
        iam_user_name=iam_user_name,
        service_user_name=service_user_name,
        key_index=key_index,
        lookups=lookups,
        actions=tuple(actions),
        warnings=tuple(warnings),
    )


def _resolve_access_key_id(
    access_key_id: str,
    *,
    policy_arn: str,
    region: str | None = None,
    signing_service: str | None = None,
) -> ResolvedCredential:
    warnings: list[str] = []

    if signing_service and signing_service not in BEDROCK_SIGNING_SERVICES:
        warnings.append(
            f"credential scope service is {signing_service!r}, not Bedrock "
            f"({', '.join(sorted(BEDROCK_SIGNING_SERVICES))}); this request may "
            "not be Bedrock traffic"
        )

    if access_key_id.startswith(_TEMPORARY_AKID_PREFIX):
        # STS session credentials have no status to flip; the only lever is a
        # policy on the identity that minted them, which the AKID does not name.
        warnings.append(
            "temporary credential: there is no IAM API to deactivate it. The "
            "issuing role is not derivable from the access key ID -- resolve it "
            "from CloudTrail, then attach the quarantine policy to that role."
        )
        return ResolvedCredential(
            kind=CredentialKind.IAM_TEMPORARY_CREDENTIAL,
            access_key_id=access_key_id,
            region=region,
            signing_service=signing_service,
            lookups=(
                LookupStep(
                    api="cloudtrail:LookupEvents",
                    params={"AccessKeyId": access_key_id},
                    select="Events[0].userIdentity.sessionContext.sessionIssuer.userName",
                    note=(
                        "CloudTrail lags 5-15 minutes. An IAM Role here means a "
                        "short-term Bedrock key; scope the quarantine to that role."
                    ),
                ),
            ),
            actions=(
                _quarantine_policy_action(
                    target_kind="role",
                    target_name="${lookup.RoleName}",
                    policy_arn=policy_arn,
                ),
            ),
            warnings=tuple(warnings),
        )

    if not access_key_id.startswith(_LONG_TERM_AKID_PREFIX):
        warnings.append(
            f"unrecognised access key ID prefix {access_key_id[:4]!r}; treating "
            "as a long-term IAM user key"
        )

    # UpdateAccessKey needs the owning user name, and no IAM API maps an access
    # key ID to its owner. Enumeration is the only first-party route.
    warnings.append(
        "the owning IAM user is not derivable from an access key ID; the "
        "enumeration lookup below is O(users) -- cache the AKID->user map in a "
        "CloudFlow Datastore, or resolve via CloudTrail instead"
    )

    return ResolvedCredential(
        kind=CredentialKind.IAM_ACCESS_KEY,
        access_key_id=access_key_id,
        region=region,
        signing_service=signing_service,
        lookups=(
            LookupStep(
                api="iam:ListAccessKeys",
                params={"UserName": "${each iam:ListUsers result}"},
                select=(
                    "AccessKeyMetadata[?AccessKeyId=="
                    f"'{access_key_id}'].UserName | [0]"
                ),
                note=(
                    "sts:GetAccessKeyInfo resolves the account but not the user. "
                    "Prefer a cached map; fall back to cloudtrail:LookupEvents."
                ),
            ),
        ),
        actions=(
            ContainmentAction(
                api="iam:UpdateAccessKey",
                params={
                    "UserName": "${lookup.UserName}",
                    "AccessKeyId": access_key_id,
                    "Status": "Inactive",
                },
                tier=2,
                reversible=True,
                undo="iam:UpdateAccessKey(Status=Active)",
                note=(
                    "Stops all AWS use of this key, not just Bedrock. Confirm "
                    "blast radius before auto-applying."
                ),
            ),
            _quarantine_policy_action(
                target_kind="user",
                target_name="${lookup.UserName}",
                policy_arn=policy_arn,
            ),
            ContainmentAction(
                api="iam:DeleteAccessKey",
                params={
                    "UserName": "${lookup.UserName}",
                    "AccessKeyId": access_key_id,
                },
                tier=3,
                reversible=False,
                note="Irreversible; gate behind approval.",
            ),
        ),
        warnings=tuple(warnings),
    )


def _resolve_service_specific_credential_id(
    credential_id: str, *, policy_arn: str
) -> ResolvedCredential:
    del policy_arn  # no identity known, so no policy target
    return ResolvedCredential(
        kind=CredentialKind.SERVICE_SPECIFIC_CREDENTIAL_ID,
        service_specific_credential_id=credential_id,
        actions=(
            ContainmentAction(
                api="iam:UpdateServiceSpecificCredential",
                params={
                    "ServiceSpecificCredentialId": credential_id,
                    "Status": "Inactive",
                },
                tier=2,
                reversible=True,
                undo="iam:UpdateServiceSpecificCredential(Status=Active)",
            ),
            ContainmentAction(
                api="iam:DeleteServiceSpecificCredential",
                params={"ServiceSpecificCredentialId": credential_id},
                tier=3,
                reversible=False,
                note="Irreversible; gate behind approval.",
            ),
        ),
        warnings=(
            "credential ID supplied directly, so the owning IAM user is unknown; "
            "call iam:ListServiceSpecificCredentials if the audit record needs it",
        ),
    )


# --- entry points ------------------------------------------------------------


def resolve(observed: str, *, policy_arn: str) -> ResolvedCredential:
    """Resolve a single observed credential or ``Authorization`` header value.

    Accepts a bare ``ABSK``/``AKIA``/``ASIA``/``ACCA`` value, or a full SigV4
    ``Authorization`` header from which the access key ID is extracted.

    Raises:
        UnresolvableCredential: the value is empty, truncated, or unrecognised.
    """
    if not observed or not observed.strip():
        raise UnresolvableCredential("empty credential")

    candidate = observed.strip()
    if candidate.lower().startswith("bearer "):
        candidate = candidate[len("bearer ") :].strip()

    sigv4 = _SIGV4_CREDENTIAL_RE.search(candidate)
    if sigv4 is not None:
        return _resolve_access_key_id(
            sigv4.group("akid"),
            policy_arn=policy_arn,
            region=sigv4.group("region"),
            signing_service=sigv4.group("service"),
        )

    if candidate.startswith(BEDROCK_API_KEY_PREFIX):
        return _resolve_bedrock_api_key(candidate, policy_arn=policy_arn)

    if candidate.startswith(_SERVICE_SPECIFIC_CRED_PREFIX) and _AKID_RE.match(candidate):
        return _resolve_service_specific_credential_id(candidate, policy_arn=policy_arn)

    if candidate.startswith(
        (_LONG_TERM_AKID_PREFIX, _TEMPORARY_AKID_PREFIX)
    ) and _AKID_RE.match(candidate):
        return _resolve_access_key_id(candidate, policy_arn=policy_arn)

    raise UnresolvableCredential(
        f"unrecognised credential shape: {redact(candidate)}"
    )


def resolve_alert(payload: dict[str, object], *, policy_arn: str) -> ResolvedCredential:
    """Resolve from an Attribute webhook payload.

    Reads ``credential`` (preferred), then ``key_hint``. A hint is usually a
    truncated key and will not decode -- that is reported as a warning-bearing
    :class:`ResolvedCredential` rather than an exception, so the flow can branch
    to the CloudTrail fallback instead of failing the execution.
    """
    provider = payload.get("provider")
    if provider is not None and provider != "bedrock":
        raise UnresolvableCredential(
            f"payload provider is {provider!r}, not 'bedrock'"
        )

    for source in ("credential", "key_hint"):
        raw = payload.get(source)
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            resolved = resolve(raw, policy_arn=policy_arn)
        except UnresolvableCredential as exc:
            if source == "key_hint":
                return ResolvedCredential(
                    kind=CredentialKind.UNKNOWN,
                    warnings=(
                        f"could not resolve key_hint ({exc}); it is probably "
                        "truncated. Fall back to CloudTrail identity resolution.",
                    ),
                )
            raise
        return resolved

    raise UnresolvableCredential(
        "payload carries neither 'credential' nor 'key_hint'"
    )
