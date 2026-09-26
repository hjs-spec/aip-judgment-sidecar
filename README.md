# AIP Judgment Sidecar 0.2

A versioned **AIP receipt prototype** with Ed25519 signatures and an explicit application policy hook. Its receipt envelope is independent of JEP Core, including current Core 0.7. For current J/D/T/V wire events use [JEP API](https://github.com/hjs-spec/jep-api) and [the Python SDK](https://github.com/hjs-spec/sdk-py).

## Install and run

Requires Python 3.10 or newer. In a virtual environment:

```sh
git clone https://github.com/hjs-spec/aip-judgment-sidecar.git
cd aip-judgment-sidecar
python -m pip install -r requirements.txt
python industrial_demo.py
```

The requirements install this local package, including its `src/aip_jep` imports. The demo does not call a real AIP service or policy engine. With no policy evaluator it produces a signed **undetermined** receipt. Missing or malformed AAT references/context are rejected before signing.

## Explicit policy decisions

```python
from aip_jep import AIPJudgmentVerifier, PolicyDecision, verify_receipt

def local_policy(aat_jti, context):
    # Illustrative application policy; authenticate the actual AAT separately.
    if context["operation"] == "read" and context["resource"].startswith("demo:"):
        return PolicyDecision("approved", "Demo policy permits this read")
    return PolicyDecision("denied", "Outside the demo policy")

verifier = AIPJudgmentVerifier(policy_evaluator=local_policy)
# receipt = verifier.issue_judgment(aat_jti, context)
# verify_receipt(receipt, independently_trusted_public_jwk)
```

The application supplies the policy evaluator and must bind it to the intended policy URI/hash. An exception or malformed decision aborts issuance. `policy_evaluated` means this callback ran, not that a credential, organization, or external truth was independently verified. `aat_jti` is a reference; this prototype does not authenticate AAT tokens.

## Receipt and key boundaries

- New receipts use `version: aip-sidecar-receipt-0.2`, `canonicalization: sorted-ascii-json-v1`, an explicit verdict/reason, policy reference, context hash and signed key identifier.
- A public-key fingerprint supplies a stable `kid`. Reloading the same private key preserves it; generating a different key changes it. A new process without a configured private key generates a new key; persist trusted key material when continuity is required.
- The sorted ASCII JSON signature encoding is retained for compatibility with the earlier signer. It is explicitly **not RFC 8785 JCS or detached JWS**. New records are distinguishable from historical `jep-v1` receipts; existing signed records are never rewritten.
- `verify_receipt` verifies the 0.2 envelope against a caller-trusted key, with key type/curve/algorithm/usage checks. It establishes signature integrity, not policy correctness, actor identity, legal responsibility or permission to execute.
- Historical 0.1 receipts are not silently upgraded or accepted by the new receipt verifier. A historical reader must explicitly select their format.

## Tests

```sh
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests cover missing input, policy failures, explicit outcomes, tampering, stable key identifiers, key metadata and legacy payload encoding. CI installs the package and exercises the documented demo and built wheel.
