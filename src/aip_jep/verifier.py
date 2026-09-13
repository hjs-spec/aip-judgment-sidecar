"""AIP receipt prototype: explicit policy evaluation, never implicit approval."""

import copy
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlsplit

from .crypto import (
    JEPAsymmetricSigner,
    canonical_payload,
    compute_content_hash,
    generate_uuid7,
    verify_payload,
)
from .models import JudgmentContext, OperationType, RiskLevel


@dataclass(frozen=True)
class PolicyDecision:
    judgment: str
    reason: str

    def __post_init__(self):
        if self.judgment not in {"approved", "denied", "undetermined"}:
            raise ValueError("Invalid policy verdict")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("A policy decision requires a reason")


def validate_request(aat_jti: str, context: JudgmentContext) -> dict:
    if not isinstance(aat_jti, str) or not aat_jti.strip():
        raise ValueError("A non-empty AAT reference is required")
    if not isinstance(context, dict):
        raise ValueError("Context must be an object")
    data = copy.deepcopy(context)
    for key in (
        "operation",
        "resource",
        "timestamp",
        "risk_level",
        "policy_uri",
        "policy_hash",
        "actor_id",
    ):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f"Missing or invalid context.{key}")
    if data["operation"] not in {value.value for value in OperationType}:
        raise ValueError("Unknown operation")
    if data["risk_level"] not in {value.value for value in RiskLevel}:
        raise ValueError("Unknown risk level")
    if not urlsplit(data["policy_uri"]).scheme:
        raise ValueError("Policy URI must be absolute")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", data["policy_hash"]):
        raise ValueError("Policy hash must be a SHA-256 digest")
    try:
        instant = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Context timestamp must be ISO 8601") from exc
    if instant.tzinfo is None:
        raise ValueError("Context timestamp must include a timezone")
    if not isinstance(data.get("metadata"), dict):
        raise ValueError("Context metadata must be an object")
    canonical_payload(data)  # Reject unsupported values and non-finite numbers.
    return data


class JEPReceipt:
    def __init__(self, data: dict):
        self.__dict__.update(copy.deepcopy(data))

    def to_json(self):
        return json.dumps(self.__dict__, indent=2, allow_nan=False)


class AIPJudgmentVerifier:
    def __init__(
        self,
        private_key_hex: Optional[str] = None,
        policy_evaluator: Optional[
            Callable[[str, JudgmentContext], PolicyDecision]
        ] = None,
    ):
        if policy_evaluator is not None and not callable(policy_evaluator):
            raise TypeError("policy_evaluator must be callable")
        self.signer = JEPAsymmetricSigner(private_key_hex)
        self.policy_evaluator = policy_evaluator
        self.verifier_id = "aip-sidecar-prototype-0.2"

    def issue_judgment(self, aat_jti: str, context: JudgmentContext) -> JEPReceipt:
        data = validate_request(aat_jti, context)
        decision = PolicyDecision("undetermined", "No policy evaluator configured")
        if self.policy_evaluator is not None:
            decision = self.policy_evaluator(aat_jti, copy.deepcopy(data))
            if not isinstance(decision, PolicyDecision):
                raise ValueError("Policy evaluator must return PolicyDecision")
        body = {
            "version": "aip-sidecar-receipt-0.2",
            "canonicalization": "sorted-ascii-json-v1",
            "receipt_id": "jep_" + generate_uuid7(),
            "aat_jti": aat_jti,
            "judgment": decision.judgment,
            "reason": decision.reason,
            "policy_evaluated": self.policy_evaluator is not None,
            "ctx_hash": compute_content_hash(data),
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "verifier": self.verifier_id,
            "key_id": self.signer.get_public_key_jwk()["kid"],
            "policy": {"uri": data["policy_uri"], "hash": data["policy_hash"]},
        }
        body["signature"] = self.signer.sign_payload(body)
        return JEPReceipt(body)

    def get_verifier_public_key(self):
        return self.signer.get_public_key_jwk()


def verify_receipt(receipt, trusted_jwk: dict) -> bool:
    """Check this prototype envelope's signature, not the policy's correctness."""
    data = receipt.__dict__ if isinstance(receipt, JEPReceipt) else receipt
    if not isinstance(data, dict) or data.get("version") != "aip-sidecar-receipt-0.2":
        return False
    if data.get("canonicalization") != "sorted-ascii-json-v1":
        return False
    return verify_payload(
        {k: v for k, v in data.items() if k != "signature"},
        data.get("signature"),
        trusted_jwk,
    )
