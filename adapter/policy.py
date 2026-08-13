"""Containment-tier policy and the CloudFlow payload builder.

Tiers:
    1  observe   -- notify + audit record, no mutation
    2  quarantine -- reversible: deactivate the credential, attach quarantine policy
    3  destroy   -- irreversible; never reachable from an inbound payload

Guardrails encoded here rather than in the flow, because they must hold even if
the flow is edited in the CloudFlow UI:

* The adapter never emits tier 3. Destruction requires a human inside CloudFlow.
* ``requested_action`` from Attribute can only *lower* the computed tier.
* Protected IAM identities are never targeted automatically.
* No secret material reaches the outbound payload.
"""

from __future__ import annotations

from dataclasses import dataclass

from resolver.bedrock import CredentialKind, ResolvedCredential

__all__ = [
    "MAX_AUTOMATED_TIER",
    "TIER_POLICY",
    "Decision",
    "build_cloudflow_payload",
    "decide_tier",
]

#: The adapter will never emit a tier above this.
MAX_AUTOMATED_TIER = 2

#: (signal, severity) -> tier. Missing severities fall back to the signal's
#: lowest entry; unknown signals observe only.
TIER_POLICY: dict[str, dict[str, int]] = {
    "leaked_key": {"info": 2, "warning": 2, "critical": 2},
    "runaway_agent": {"info": 1, "warning": 2, "critical": 2},
    "budget_overrun": {"info": 1, "warning": 1, "critical": 2},
    "token_spike": {"info": 1, "warning": 1, "critical": 1},
    "anomalous_workload": {"info": 1, "warning": 1, "critical": 1},
}

#: Tier 2 signals that still require a human to approve before the mutation runs.
#: Everything else at tier 2 auto-applies -- the point of the system is speed.
REQUIRES_APPROVAL: frozenset[str] = frozenset({"budget_overrun"})


@dataclass(frozen=True)
class Decision:
    tier: int
    auto_apply: bool
    requires_approval: bool
    rationale: str


def decide_tier(
    signal: str,
    severity: str,
    *,
    requested_action: str | None = None,
    resolved: ResolvedCredential | None = None,
    protected_iam_users: frozenset[str] = frozenset(),
) -> Decision:
    """Compute the containment tier for an alert."""
    by_severity = TIER_POLICY.get(signal)
    if by_severity is None:
        return Decision(
            tier=1,
            auto_apply=False,
            requires_approval=False,
            rationale=f"unknown signal {signal!r}; observe only",
        )

    tier = by_severity.get(severity, min(by_severity.values()))
    rationale = f"{signal}/{severity} -> tier {tier}"

    if tier > MAX_AUTOMATED_TIER:
        tier = MAX_AUTOMATED_TIER
        rationale += f"; capped at tier {MAX_AUTOMATED_TIER}"

    # Advisory de-escalation only. An inbound payload must never be able to
    # raise the tier -- that would make a spoofed alert more dangerous.
    if requested_action == "observe" and tier > 1:
        tier = 1
        rationale += "; lowered to 1 by requested_action=observe"

    if resolved is not None:
        if not resolved.is_actionable and tier > 1:
            tier = 1
            rationale += "; lowered to 1, no containment action available"
        elif (
            resolved.iam_user_name
            and resolved.iam_user_name in protected_iam_users
            and tier > 1
        ):
            tier = 1
            rationale += (
                f"; lowered to 1, {resolved.iam_user_name!r} is a protected identity"
            )

    requires_approval = tier >= 2 and signal in REQUIRES_APPROVAL
    return Decision(
        tier=tier,
        auto_apply=tier >= 2 and not requires_approval,
        requires_approval=requires_approval,
        rationale=rationale,
    )


def _params_json(params: dict[str, object]) -> str:
    import json

    return json.dumps(params, separators=(",", ":"), sort_keys=True)


def build_cloudflow_payload(
    alert: dict[str, object],
    resolved: ResolvedCredential,
    decision: Decision,
    *,
    quarantine_policy_arn: str,
    key_hint: str,
    forwarded_at: str,
) -> dict[str, object]:
    """Assemble the body POSTed to the CloudFlow webhook.

    Must stay field-for-field compatible with
    ``contracts/cloudflow-trigger.v1.sample.json`` -- CloudFlow derives its
    payload schema from that sample, and any field missing from it is invisible
    to downstream nodes.

    Carries no secret material: only the resolved identity and the redacted hint.
    """
    tiered = [a for a in resolved.actions if a.tier <= decision.tier]
    primary_action = tiered[0] if tiered else None
    primary_lookup = resolved.lookups[0] if resolved.lookups else None

    alert_id = str(alert.get("alert_id", ""))
    warnings = list(resolved.warnings)

    return {
        "alert_id": alert_id,
        "idempotency_key": f"{alert_id}:tier{decision.tier}",
        "contract_version": "1",
        "detected_at": alert.get("detected_at", ""),
        "forwarded_at": forwarded_at,
        "severity": alert.get("severity", ""),
        "signal": alert.get("signal", ""),
        "reason": alert.get("reason", ""),
        "provider": "bedrock",
        "tier": decision.tier,
        "auto_apply": decision.auto_apply,
        "requires_approval": decision.requires_approval,
        "tier_rationale": decision.rationale,
        "credential_kind": resolved.kind.value,
        "key_hint": key_hint,
        "aws_account_id": resolved.account_id or "",
        "iam_user_name": resolved.iam_user_name or "",
        "service_user_name": resolved.service_user_name or "",
        "key_index": resolved.key_index if resolved.key_index is not None else -1,
        "access_key_id": resolved.access_key_id or "",
        "service_specific_credential_id": resolved.service_specific_credential_id or "",
        "region": resolved.region or "",
        "signing_service": resolved.signing_service or "",
        "workload_name": alert.get("workload_name", ""),
        "principal_type": alert.get("principal_type", "unknown"),
        "observed_spend_usd": alert.get("observed_spend_usd", 0),
        "observed_window_minutes": alert.get("observed_window_minutes", 0),
        "needs_external_lookup": resolved.needs_external_lookup,
        "is_actionable": resolved.is_actionable,
        "primary_lookup_api": primary_lookup.api if primary_lookup else "",
        "primary_lookup_params_json": (
            _params_json(dict(primary_lookup.params)) if primary_lookup else "{}"
        ),
        "primary_lookup_select": primary_lookup.select if primary_lookup else "",
        "primary_action_api": primary_action.api if primary_action else "",
        "primary_action_params_json": (
            _params_json(dict(primary_action.params)) if primary_action else "{}"
        ),
        "primary_action_reversible": (
            primary_action.reversible if primary_action else False
        ),
        "primary_action_undo": (primary_action.undo or "") if primary_action else "",
        "quarantine_policy_arn": quarantine_policy_arn,
        "warnings_text": "; ".join(warnings),
        "lookups": [
            {
                "api": lookup.api,
                "params_json": _params_json(dict(lookup.params)),
                "select": lookup.select,
                "note": lookup.note,
            }
            for lookup in resolved.lookups
        ],
        "actions": [
            {
                "api": action.api,
                "params_json": _params_json(dict(action.params)),
                "tier": action.tier,
                "reversible": action.reversible,
                "undo": action.undo or "",
                "note": action.note,
            }
            for action in tiered
        ],
        "warnings": warnings,
    }


def assert_no_secret(payload: dict[str, object], credential: str | None) -> None:
    """Belt-and-braces check that the credential did not leak into the payload.

    Cheap insurance against a future edit to the builder: the whole point of the
    adapter is that live credentials never reach the DoiT platform.
    """
    if not credential or len(credential) < 12:
        return

    import json

    serialised = json.dumps(payload)
    # The tail is the secret half for ABSK and the signature for SigV4.
    for fragment in (credential, credential[-16:]):
        if fragment and fragment in serialised:
            raise AssertionError(
                "refusing to forward: credential material found in outbound payload"
            )
