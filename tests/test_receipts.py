import copy

import pytest
from aip_jep import AIPJudgmentVerifier, PolicyDecision, verify_receipt
from aip_jep.crypto import JEPAsymmetricSigner, canonical_payload, compute_content_hash


@pytest.fixture
def context():
    return {
        "operation": "read",
        "resource": "demo:data",
        "timestamp": "2026-09-13T00:00:00Z",
        "risk_level": "low",
        "policy_uri": "urn:demo:policy",
        "policy_hash": "sha256:" + "a" * 64,
        "actor_id": "demo:agent",
        "metadata": {"unicode": "中文", "value": 1e-7},
    }


def test_no_evaluator_never_approves(context):
    verifier = AIPJudgmentVerifier()
    receipt = verifier.issue_judgment("aat:1", context)
    assert receipt.judgment == "undetermined" and not receipt.policy_evaluated
    assert verify_receipt(receipt, verifier.get_verifier_public_key())
    assert receipt.ctx_hash == compute_content_hash(context)


@pytest.mark.parametrize("verdict", ["approved", "denied", "undetermined"])
def test_only_explicit_policy_decisions_can_be_signed(context, verdict):
    verifier = AIPJudgmentVerifier(
        policy_evaluator=lambda aat, ctx: PolicyDecision(verdict, "local test policy")
    )
    receipt = verifier.issue_judgment("aat:1", context)
    assert receipt.judgment == verdict and receipt.policy_evaluated
    assert verify_receipt(receipt, verifier.get_verifier_public_key())
    tampered = copy.deepcopy(receipt.__dict__)
    tampered["policy"]["hash"] = "sha256:" + "b" * 64
    assert not verify_receipt(tampered, verifier.get_verifier_public_key())


@pytest.mark.parametrize(
    "field",
    [
        "operation",
        "resource",
        "timestamp",
        "risk_level",
        "policy_uri",
        "policy_hash",
        "actor_id",
        "metadata",
    ],
)
def test_missing_context_is_rejected_before_policy_runs(context, field):
    context.pop(field)

    def must_not_run(*args):
        pytest.fail("invalid input reached policy evaluator")

    with pytest.raises(ValueError):
        AIPJudgmentVerifier(policy_evaluator=must_not_run).issue_judgment(
            "aat:1", context
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"timestamp": "2026-01-01"},
        {"policy_hash": "abc"},
        {"risk_level": "unknown"},
        {"operation": "unknown"},
        {"metadata": {"value": float("nan")}},
    ],
)
def test_invalid_context_rejected(context, changes):
    context.update(changes)
    with pytest.raises(ValueError):
        AIPJudgmentVerifier().issue_judgment("aat:1", context)


def test_empty_aat_and_context_rejected(context):
    with pytest.raises(ValueError):
        AIPJudgmentVerifier().issue_judgment("", context)
    with pytest.raises(ValueError):
        AIPJudgmentVerifier().issue_judgment("aat:1", {})


def test_policy_failure_and_bad_return_never_create_receipt(context):
    def unavailable(*args):
        raise RuntimeError("offline")

    with pytest.raises(RuntimeError):
        AIPJudgmentVerifier(policy_evaluator=unavailable).issue_judgment(
            "aat:1", context
        )
    with pytest.raises(ValueError):
        AIPJudgmentVerifier(policy_evaluator=lambda *args: True).issue_judgment(
            "aat:1", context
        )


def test_policy_cannot_mutate_the_context_bound_into_receipt(context):
    def policy(aat, ctx):
        ctx["resource"] = "modified"
        return PolicyDecision("denied", "test")

    receipt = AIPJudgmentVerifier(policy_evaluator=policy).issue_judgment(
        "aat:1", context
    )
    assert receipt.ctx_hash == compute_content_hash(context)


def test_key_identifiers_are_stable_across_time_and_restart(monkeypatch):
    signer = JEPAsymmetricSigner()
    monkeypatch.setattr("aip_jep.crypto.time.time", lambda: 1)
    before = signer.get_public_key_jwk()
    monkeypatch.setattr("aip_jep.crypto.time.time", lambda: 2)
    assert signer.get_public_key_jwk() == before
    assert (
        JEPAsymmetricSigner(signer.export_private_key()).get_public_key_jwk() == before
    )
    assert JEPAsymmetricSigner().get_public_key_jwk()["kid"] != before["kid"]


@pytest.mark.parametrize(
    "metadata",
    [
        {"kty": "EC"},
        {"crv": "P-256"},
        {"alg": "ES256"},
        {"use": "enc"},
        {"key_ops": ["sign"]},
        {"kid": "unrelated"},
    ],
)
def test_trusted_key_metadata_must_match(context, metadata):
    verifier = AIPJudgmentVerifier()
    receipt = verifier.issue_judgment("aat:1", context)
    key = verifier.get_verifier_public_key()
    key.update(metadata)
    assert not verify_receipt(receipt, key)


def test_legacy_payload_encoding_is_preserved():
    assert canonical_payload({"z": 1e-7, "a": "中"}) == b'{"a":"\\u4e2d","z":1e-07}'
