"""Tests for signature verification, tier policy, and payload construction.

Covers the pure units only -- no AWS, no network.
"""

from __future__ import annotations

import base64
import json
import unittest

from adapter.policy import (
    MAX_AUTOMATED_TIER,
    Decision,
    assert_no_secret,
    build_cloudflow_payload,
    decide_tier,
)
from adapter.signature import SignatureError, sign, verify
from resolver.bedrock import CredentialKind, resolve

POLICY_ARN = "arn:aws:iam::123456789012:policy/AttributeQuarantineBedrock"
SECRET = "s3cr3tPLAINTEXTdonotleak" + "A" * 20
NOW = 1755093723


def make_absk(service_user_name: str = "BedrockAPIKey-abcd+1-at-123456789012") -> str:
    raw = f"{service_user_name}:{SECRET}".encode()
    return "ABSK" + base64.b64encode(raw).decode().rstrip("=")


def alert(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "alert_id": "atr_01HZX3K5V8QG7YHN2M4P6R9TBC",
        "detected_at": "2026-08-13T14:22:03Z",
        "severity": "critical",
        "signal": "runaway_agent",
        "reason": "42k requests in 5m, 61x baseline",
        "provider": "bedrock",
        "credential": make_absk(),
        "workload_name": "payments-agent",
        "principal_type": "non_human",
        "observed_spend_usd": 4820.5,
        "observed_window_minutes": 5,
    }
    base.update(overrides)
    return base


class SignatureTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        body = b'{"alert_id":"a"}'
        verify(body, sign(body, "shh", NOW), ["shh"], now=NOW)

    def test_tampered_body_fails(self) -> None:
        header = sign(b'{"tier":1}', "shh", NOW)
        with self.assertRaises(SignatureError):
            verify(b'{"tier":3}', header, ["shh"], now=NOW)

    def test_wrong_secret_fails(self) -> None:
        body = b"{}"
        with self.assertRaises(SignatureError):
            verify(body, sign(body, "shh", NOW), ["different"], now=NOW)

    def test_stale_request_is_rejected(self) -> None:
        body = b"{}"
        header = sign(body, "shh", NOW - 600)
        with self.assertRaises(SignatureError) as ctx:
            verify(body, header, ["shh"], now=NOW)
        self.assertIn("tolerance", str(ctx.exception))

    def test_future_timestamp_is_rejected(self) -> None:
        body = b"{}"
        with self.assertRaises(SignatureError):
            verify(body, sign(body, "shh", NOW + 600), ["shh"], now=NOW)

    def test_replay_with_fresh_timestamp_fails(self) -> None:
        # The timestamp is inside the signed material, so an attacker cannot
        # refresh it without invalidating the digest.
        body = b"{}"
        captured = sign(body, "shh", NOW - 600)
        digest = captured.split("v1=")[1]
        with self.assertRaises(SignatureError):
            verify(body, f"t={NOW},v1={digest}", ["shh"], now=NOW)

    def test_secret_rotation_accepts_either(self) -> None:
        body = b"{}"
        for secret in ("old", "new"):
            with self.subTest(secret=secret):
                verify(body, sign(body, secret, NOW), ["old", "new"], now=NOW)

    def test_missing_header_fails(self) -> None:
        for header in (None, ""):
            with self.subTest(header=header), self.assertRaises(SignatureError):
                verify(b"{}", header, ["shh"], now=NOW)

    def test_unconfigured_secret_does_not_fail_open(self) -> None:
        body = b"{}"
        for secrets in ([], [""], ["", ""]):
            with self.subTest(secrets=secrets), self.assertRaises(SignatureError):
                verify(body, sign(body, "shh", NOW), secrets, now=NOW)

    def test_malformed_headers(self) -> None:
        cases = ["v1=" + "a" * 64, f"t={NOW}", "garbage", f"t=notanumber,v1={'a' * 64}"]
        for header in cases:
            with self.subTest(header=header), self.assertRaises(SignatureError):
                verify(b"{}", header, ["shh"], now=NOW)

    def test_non_hex_signature_is_rejected(self) -> None:
        with self.assertRaises(SignatureError):
            verify(b"{}", f"t={NOW},v1=zzzz", ["shh"], now=NOW)


class TierPolicyTests(unittest.TestCase):
    def test_leaked_key_contains_at_every_severity(self) -> None:
        for severity in ("info", "warning", "critical"):
            with self.subTest(severity=severity):
                self.assertEqual(decide_tier("leaked_key", severity).tier, 2)

    def test_token_spike_only_observes(self) -> None:
        decision = decide_tier("token_spike", "critical")
        self.assertEqual(decision.tier, 1)
        self.assertFalse(decision.auto_apply)

    def test_budget_overrun_requires_approval(self) -> None:
        decision = decide_tier("budget_overrun", "critical")
        self.assertEqual(decision.tier, 2)
        self.assertTrue(decision.requires_approval)
        self.assertFalse(decision.auto_apply)

    def test_runaway_agent_auto_applies(self) -> None:
        decision = decide_tier("runaway_agent", "critical")
        self.assertEqual(decision.tier, 2)
        self.assertTrue(decision.auto_apply)
        self.assertFalse(decision.requires_approval)

    def test_unknown_signal_observes(self) -> None:
        decision = decide_tier("brand_new_signal", "critical")
        self.assertEqual(decision.tier, 1)
        self.assertIn("unknown signal", decision.rationale)

    def test_requested_action_can_lower_tier(self) -> None:
        decision = decide_tier("leaked_key", "critical", requested_action="observe")
        self.assertEqual(decision.tier, 1)

    def test_requested_action_can_never_raise_tier(self) -> None:
        # A spoofed or replayed alert must not be able to escalate.
        decision = decide_tier("token_spike", "info", requested_action="contain")
        self.assertEqual(decision.tier, 1)

    def test_adapter_never_emits_tier_three(self) -> None:
        for signal in ("leaked_key", "runaway_agent", "budget_overrun"):
            for severity in ("info", "warning", "critical"):
                with self.subTest(signal=signal, severity=severity):
                    self.assertLessEqual(
                        decide_tier(signal, severity).tier, MAX_AUTOMATED_TIER
                    )

    def test_protected_user_is_not_auto_contained(self) -> None:
        resolved = resolve(make_absk(), policy_arn=POLICY_ARN)
        decision = decide_tier(
            "leaked_key",
            "critical",
            resolved=resolved,
            protected_iam_users=frozenset({"BedrockAPIKey-abcd"}),
        )
        self.assertEqual(decision.tier, 1)
        self.assertIn("protected identity", decision.rationale)

    def test_unactionable_credential_downgrades_to_observe(self) -> None:
        unresolved = resolve("ACCAEXAMPLE123EXAMPLE", policy_arn=POLICY_ARN)
        object.__setattr__(unresolved, "actions", ())
        decision = decide_tier("leaked_key", "critical", resolved=unresolved)
        self.assertEqual(decision.tier, 1)
        self.assertIn("no containment action", decision.rationale)


class PayloadTests(unittest.TestCase):
    def build(self, **overrides: object) -> dict[str, object]:
        data = alert(**overrides)
        resolved = resolve(str(data["credential"]), policy_arn=POLICY_ARN)
        decision = decide_tier(str(data["signal"]), str(data["severity"]), resolved=resolved)
        return build_cloudflow_payload(
            data,
            resolved,
            decision,
            quarantine_policy_arn=POLICY_ARN,
            key_hint="ABSK...[redacted:112]",
            forwarded_at="2026-08-13T14:22:05Z",
        )

    def test_carries_resolved_identity(self) -> None:
        payload = self.build()
        self.assertEqual(payload["iam_user_name"], "BedrockAPIKey-abcd")
        self.assertEqual(payload["aws_account_id"], "123456789012")
        self.assertEqual(payload["credential_kind"], CredentialKind.BEDROCK_LONG_TERM_API_KEY.value)
        self.assertEqual(payload["tier"], 2)

    def test_no_secret_material_forwarded(self) -> None:
        payload = self.build()
        serialised = json.dumps(payload)
        self.assertNotIn(SECRET, serialised)
        self.assertNotIn(str(alert()["credential"]), serialised)

    def test_assert_no_secret_catches_a_leak(self) -> None:
        credential = make_absk()
        with self.assertRaises(AssertionError):
            assert_no_secret({"oops": credential}, credential)

    def test_assert_no_secret_catches_tail_leak(self) -> None:
        credential = make_absk()
        with self.assertRaises(AssertionError):
            assert_no_secret({"oops": credential[-16:]}, credential)

    def test_assert_no_secret_passes_clean_payload(self) -> None:
        assert_no_secret(self.build(), make_absk())

    def test_actions_are_filtered_to_the_decided_tier(self) -> None:
        payload = self.build()
        tiers = {action["tier"] for action in payload["actions"]}
        self.assertTrue(tiers)
        self.assertTrue(all(tier <= 2 for tier in tiers))

    def test_observe_tier_emits_no_actions(self) -> None:
        payload = self.build(signal="token_spike")
        self.assertEqual(payload["tier"], 1)
        self.assertEqual(payload["actions"], [])
        self.assertEqual(payload["primary_action_api"], "")

    def test_idempotency_key_includes_tier(self) -> None:
        # Same alert escalating from observe to contain must not be deduped away.
        self.assertNotEqual(
            self.build(signal="token_spike")["idempotency_key"],
            self.build(signal="runaway_agent")["idempotency_key"],
        )

    def test_params_json_is_parseable(self) -> None:
        payload = self.build()
        self.assertEqual(
            json.loads(str(payload["primary_action_params_json"]))["Status"], "Inactive"
        )
        for action in payload["actions"]:
            json.loads(str(action["params_json"]))
        for lookup in payload["lookups"]:
            json.loads(str(lookup["params_json"]))

    def test_matches_contract_sample_fields(self) -> None:
        # CloudFlow derives its schema from the Sample JSON; a field the builder
        # emits but the sample omits is invisible to downstream nodes.
        from pathlib import Path

        sample_path = (
            Path(__file__).resolve().parents[1]
            / "contracts"
            / "cloudflow-trigger.v1.sample.json"
        )
        sample = json.loads(sample_path.read_text())
        sample_fields = {k for k in sample if not k.startswith("_")}
        built_fields = set(self.build())

        missing_from_sample = built_fields - sample_fields
        self.assertEqual(
            missing_from_sample,
            set(),
            f"fields emitted but absent from the Sample JSON: {sorted(missing_from_sample)}",
        )


class DecisionDataclassTests(unittest.TestCase):
    def test_decision_is_frozen(self) -> None:
        decision = Decision(tier=2, auto_apply=True, requires_approval=False, rationale="x")
        with self.assertRaises(Exception):
            decision.tier = 3  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
