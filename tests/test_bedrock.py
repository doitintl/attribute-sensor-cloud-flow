"""Tests for the Bedrock credential resolver.

Assertions tagged UNVERIFIED_AGAINST_REAL_KEY depend on the published ``ABSK``
layout rather than a live sample. Confirm them by minting a throwaway key on a
sandbox account and running ``python -m resolver.cli <key>``.
"""

from __future__ import annotations

import base64
import json
import unittest

from resolver.bedrock import (
    BEARER_TOKEN_ACTIONS,
    CredentialKind,
    UnresolvableCredential,
    redact,
    resolve,
    resolve_alert,
)

POLICY_ARN = "arn:aws:iam::123456789012:policy/AttributeQuarantineBedrock"

# Distinctive so leak assertions cannot pass by accident.
SECRET = "s3cr3tPLAINTEXTdonotleak" + "A" * 20


def make_absk(service_user_name: str, secret: str = SECRET, *, urlsafe: bool = False) -> str:
    """Build a synthetic long-term Bedrock API key."""
    raw = f"{service_user_name}:{secret}".encode()
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return "ABSK" + encoder(raw).decode().rstrip("=")


def sigv4_header(akid: str, service: str = "bedrock", region: str = "us-east-1") -> str:
    return (
        f"AWS4-HMAC-SHA256 Credential={akid}/20260813/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=" + "f" * 64
    )


class LongTermApiKeyTests(unittest.TestCase):
    """UNVERIFIED_AGAINST_REAL_KEY: layout from the published teardown."""

    def test_resolves_auto_created_user(self) -> None:
        result = resolve(make_absk("BedrockAPIKey-abcd-at-123456789012"), policy_arn=POLICY_ARN)

        self.assertEqual(result.kind, CredentialKind.BEDROCK_LONG_TERM_API_KEY)
        self.assertEqual(result.iam_user_name, "BedrockAPIKey-abcd")
        self.assertEqual(result.account_id, "123456789012")
        self.assertIsNone(result.key_index)
        self.assertTrue(result.is_actionable)

    def test_secondary_key_index_is_split_off(self) -> None:
        result = resolve(make_absk("BedrockAPIKey-abcd+1-at-123456789012"), policy_arn=POLICY_ARN)

        self.assertEqual(result.iam_user_name, "BedrockAPIKey-abcd")
        self.assertEqual(result.key_index, 1)
        self.assertEqual(result.account_id, "123456789012")

    def test_key_on_a_customer_named_iam_user(self) -> None:
        result = resolve(make_absk("payments-agent+2-at-999888777666"), policy_arn=POLICY_ARN)

        self.assertEqual(result.iam_user_name, "payments-agent")
        self.assertEqual(result.key_index, 2)
        self.assertEqual(result.account_id, "999888777666")

    def test_plus_in_user_name_without_digits_is_not_an_index(self) -> None:
        result = resolve(make_absk("weird+user-at-123456789012"), policy_arn=POLICY_ARN)

        self.assertEqual(result.iam_user_name, "weird+user")
        self.assertIsNone(result.key_index)

    def test_lookup_matches_on_full_service_user_name(self) -> None:
        service_user_name = "BedrockAPIKey-abcd+1-at-123456789012"
        result = resolve(make_absk(service_user_name), policy_arn=POLICY_ARN)

        (lookup,) = result.lookups
        self.assertEqual(lookup.api, "iam:ListServiceSpecificCredentials")
        self.assertEqual(lookup.params["UserName"], "BedrockAPIKey-abcd")
        self.assertEqual(lookup.params["ServiceName"], "bedrock.amazonaws.com")
        # Matching the whole ServiceUserName is what disambiguates primary from
        # secondary when one user holds both keys.
        self.assertIn(service_user_name, lookup.select)

    def test_tier_two_action_is_reversible_deactivation(self) -> None:
        result = resolve(make_absk("BedrockAPIKey-abcd-at-123456789012"), policy_arn=POLICY_ARN)
        tier2 = [a for a in result.actions if a.tier == 2]

        deactivate = tier2[0]
        self.assertEqual(deactivate.api, "iam:UpdateServiceSpecificCredential")
        self.assertEqual(deactivate.params["Status"], "Inactive")
        self.assertTrue(deactivate.reversible)
        self.assertTrue(all(a.reversible for a in tier2))

    def test_tier_three_action_is_flagged_irreversible(self) -> None:
        result = resolve(make_absk("BedrockAPIKey-abcd-at-123456789012"), policy_arn=POLICY_ARN)
        tier3 = [a for a in result.actions if a.tier == 3]

        self.assertTrue(tier3)
        self.assertTrue(all(not a.reversible for a in tier3))
        self.assertTrue(all(a.undo is None for a in tier3))

    def test_quarantine_note_names_both_bearer_token_actions(self) -> None:
        # Denying only bedrock:CallWithBearerToken leaves Mantle spending.
        result = resolve(make_absk("BedrockAPIKey-abcd-at-123456789012"), policy_arn=POLICY_ARN)
        attach = next(a for a in result.actions if a.api == "iam:AttachUserPolicy")

        for action in BEARER_TOKEN_ACTIONS:
            self.assertIn(action, attach.note)
        self.assertEqual(attach.params["PolicyArn"], POLICY_ARN)
        self.assertEqual(attach.undo, "iam:DetachUserPolicy")

    def test_urlsafe_base64_alphabet_is_decoded_correctly(self) -> None:
        # The permissive decoder silently drops '-' and '_', which would corrupt
        # the user name rather than fail loudly.
        service_user_name = "BedrockAPIKey-ab_cd-at-123456789012"
        result = resolve(make_absk(service_user_name, urlsafe=True), policy_arn=POLICY_ARN)

        self.assertEqual(result.service_user_name, service_user_name)

    def test_missing_account_suffix_warns_but_still_resolves(self) -> None:
        result = resolve(make_absk("legacy-key-name"), policy_arn=POLICY_ARN)

        self.assertIsNone(result.account_id)
        self.assertEqual(result.iam_user_name, "legacy-key-name")
        self.assertTrue(any("-at-" in w for w in result.warnings))

    def test_bearer_prefix_is_stripped(self) -> None:
        key = make_absk("BedrockAPIKey-abcd-at-123456789012")
        self.assertEqual(
            resolve(f"Bearer {key}", policy_arn=POLICY_ARN).iam_user_name,
            "BedrockAPIKey-abcd",
        )


class SecretHandlingTests(unittest.TestCase):
    def test_secret_never_appears_in_result(self) -> None:
        result = resolve(make_absk("BedrockAPIKey-abcd-at-123456789012"), policy_arn=POLICY_ARN)

        serialised = json.dumps(result.to_dict())
        self.assertNotIn(SECRET, serialised)
        self.assertNotIn(SECRET, repr(result))

    def test_redact_drops_the_tail(self) -> None:
        key = make_absk("BedrockAPIKey-abcd-at-123456789012")
        hint = redact(key)

        self.assertTrue(hint.startswith("ABSK"))
        self.assertNotIn(SECRET, hint)
        # The tail is the secret for ABSK and the signature for SigV4.
        self.assertNotIn(key[-8:], hint)

    def test_unresolvable_error_message_is_redacted(self) -> None:
        with self.assertRaises(UnresolvableCredential) as ctx:
            resolve("sk-live-" + SECRET, policy_arn=POLICY_ARN)

        self.assertNotIn(SECRET, str(ctx.exception))


class SigV4Tests(unittest.TestCase):
    def test_long_term_access_key_from_authorization_header(self) -> None:
        result = resolve(sigv4_header("AKIAIOSFODNN7EXAMPLE"), policy_arn=POLICY_ARN)

        self.assertEqual(result.kind, CredentialKind.IAM_ACCESS_KEY)
        self.assertEqual(result.access_key_id, "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(result.region, "us-east-1")
        self.assertEqual(result.signing_service, "bedrock")

    def test_access_key_requires_owner_lookup(self) -> None:
        # No IAM API maps an access key ID to its owning user.
        result = resolve(sigv4_header("AKIAIOSFODNN7EXAMPLE"), policy_arn=POLICY_ARN)

        self.assertTrue(result.needs_external_lookup)
        self.assertEqual(result.lookups[0].api, "iam:ListAccessKeys")
        self.assertTrue(any("not derivable" in w for w in result.warnings))
        update = next(a for a in result.actions if a.api == "iam:UpdateAccessKey")
        self.assertEqual(update.params["UserName"], "${lookup.UserName}")

    def test_temporary_credential_cannot_be_deactivated(self) -> None:
        result = resolve(sigv4_header("ASIAIOSFODNN7EXAMPLE"), policy_arn=POLICY_ARN)

        self.assertEqual(result.kind, CredentialKind.IAM_TEMPORARY_CREDENTIAL)
        self.assertTrue(any("no IAM API to deactivate" in w for w in result.warnings))
        # Only lever is a policy on the issuing role, via CloudTrail.
        self.assertEqual(result.lookups[0].api, "cloudtrail:LookupEvents")
        self.assertEqual(
            [a.api for a in result.actions], ["iam:AttachRolePolicy"]
        )

    def test_mantle_endpoint_is_recognised_as_bedrock(self) -> None:
        result = resolve(
            sigv4_header("AKIAIOSFODNN7EXAMPLE", service="bedrock-mantle"),
            policy_arn=POLICY_ARN,
        )

        self.assertEqual(result.signing_service, "bedrock-mantle")
        self.assertFalse(any("not Bedrock traffic" in w for w in result.warnings))

    def test_non_bedrock_service_scope_warns(self) -> None:
        result = resolve(sigv4_header("AKIAIOSFODNN7EXAMPLE", service="s3"), policy_arn=POLICY_ARN)

        self.assertTrue(any("not Bedrock" in w for w in result.warnings))


class BareIdentifierTests(unittest.TestCase):
    def test_bare_access_key_id(self) -> None:
        result = resolve("AKIAIOSFODNN7EXAMPLE", policy_arn=POLICY_ARN)

        self.assertEqual(result.kind, CredentialKind.IAM_ACCESS_KEY)
        self.assertIsNone(result.signing_service)

    def test_service_specific_credential_id_passes_through(self) -> None:
        result = resolve("ACCAEXAMPLE123EXAMPLE", policy_arn=POLICY_ARN)

        self.assertEqual(result.kind, CredentialKind.SERVICE_SPECIFIC_CREDENTIAL_ID)
        self.assertEqual(result.service_specific_credential_id, "ACCAEXAMPLE123EXAMPLE")
        deactivate = result.actions[0]
        self.assertEqual(deactivate.params["ServiceSpecificCredentialId"], "ACCAEXAMPLE123EXAMPLE")
        self.assertFalse(result.needs_external_lookup)


class MalformedInputTests(unittest.TestCase):
    def test_empty_credential(self) -> None:
        for value in ("", "   "):
            with self.subTest(value=value), self.assertRaises(UnresolvableCredential):
                resolve(value, policy_arn=POLICY_ARN)

    def test_absk_with_no_payload(self) -> None:
        with self.assertRaises(UnresolvableCredential):
            resolve("ABSK", policy_arn=POLICY_ARN)

    def test_absk_with_invalid_base64(self) -> None:
        with self.assertRaises(UnresolvableCredential):
            resolve("ABSK!!!not-base64!!!", policy_arn=POLICY_ARN)

    def test_absk_payload_without_separator(self) -> None:
        payload = base64.b64encode(b"NoColonHere").decode().rstrip("=")
        with self.assertRaises(UnresolvableCredential) as ctx:
            resolve("ABSK" + payload, policy_arn=POLICY_ARN)

        self.assertIn("':'", str(ctx.exception))

    def test_absk_payload_with_empty_service_user_name(self) -> None:
        payload = base64.b64encode(b":secret").decode().rstrip("=")
        with self.assertRaises(UnresolvableCredential):
            resolve("ABSK" + payload, policy_arn=POLICY_ARN)

    def test_unrecognised_shape(self) -> None:
        with self.assertRaises(UnresolvableCredential):
            resolve("sk-ant-api03-nope", policy_arn=POLICY_ARN)


class AlertPayloadTests(unittest.TestCase):
    def test_resolves_from_credential_field(self) -> None:
        payload = {
            "provider": "bedrock",
            "credential": make_absk("BedrockAPIKey-abcd-at-123456789012"),
        }
        self.assertEqual(
            resolve_alert(payload, policy_arn=POLICY_ARN).iam_user_name,
            "BedrockAPIKey-abcd",
        )

    def test_wrong_provider_is_rejected(self) -> None:
        with self.assertRaises(UnresolvableCredential):
            resolve_alert({"provider": "anthropic", "credential": "x"}, policy_arn=POLICY_ARN)

    def test_truncated_hint_degrades_instead_of_raising(self) -> None:
        # A truncated hint must not fail the flow execution -- it should branch
        # to the CloudTrail fallback.
        payload = {"provider": "bedrock", "key_hint": "ABSKQmVkcm9ja0FQSUtleS..."}
        result = resolve_alert(payload, policy_arn=POLICY_ARN)

        self.assertEqual(result.kind, CredentialKind.UNKNOWN)
        self.assertFalse(result.is_actionable)
        self.assertTrue(any("CloudTrail" in w for w in result.warnings))

    def test_credential_preferred_over_hint(self) -> None:
        payload = {
            "provider": "bedrock",
            "credential": make_absk("BedrockAPIKey-abcd-at-123456789012"),
            "key_hint": "ABSKtruncated...",
        }
        self.assertEqual(
            resolve_alert(payload, policy_arn=POLICY_ARN).iam_user_name,
            "BedrockAPIKey-abcd",
        )

    def test_payload_with_no_credential_fields(self) -> None:
        with self.assertRaises(UnresolvableCredential):
            resolve_alert({"provider": "bedrock", "workload_name": "x"}, policy_arn=POLICY_ARN)

    def test_missing_provider_is_accepted(self) -> None:
        payload = {"credential": make_absk("BedrockAPIKey-abcd-at-123456789012")}
        self.assertEqual(
            resolve_alert(payload, policy_arn=POLICY_ARN).iam_user_name,
            "BedrockAPIKey-abcd",
        )


if __name__ == "__main__":
    unittest.main()
