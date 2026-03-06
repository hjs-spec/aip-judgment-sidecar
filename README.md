# AIP Judgment Sidecar (HJS Reference Implementation)

This repository provides an industrial-grade, **non-intrusive** implementation of the **Heterogeneous Judgment Service (HJS)** for the **AI Proxy (AIP)** ecosystem.

It serves as a "Responsibility Anchor," allowing AIP to delegate complex policy judgments to a specialized sidecar without modifying its core identity or access control logic.

## 🌟 Key Features

* **Chronological Traceability**: Uses **UUIDv7 (RFC 9562)** for receipt IDs, enabling high-performance database indexing and time-ordered audit trails.
* **Cryptographic Accountability**: Implements **Ed25519 (EdDSA)** asymmetric signatures for multi-channel verification and non-repudiation.
* **Structured Context Binding**: Ensures every judgment is cryptographically tied to the specific operation context (resource, risk level, and policy hash).
* **Zero-Intrusion Architecture**: Designed to run as a sidecar, integrating with AIP via standard JSON-based verification requests.

## 🏗️ Architecture

In the AIP-HJS integrated flow, the Sidecar acts as a specialized "Judicial Branch":

1. **AIP Proxy** intercepts a sensitive tool call.
2. **AIP Proxy** sends the Agent's AAT (Accountability Attachment Token) and the operation context to the **HJS Sidecar**.
3. **HJS Sidecar** evaluates the request against the anchored policy.
4. **HJS Sidecar** issues a signed **HJS Receipt** (UUIDv7 based).
5. **AIP Proxy** attaches the receipt to the final execution request.

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/hjs-spec/aip-judgment-sidecar.git
cd aip-judgment-sidecar

# Install dependencies
pip install -r requirements.txt

```

### 2. Run the Industrial Demo

The demo showcases the generation of a time-ordered receipt with Ed25519 signature:

```bash
python industrial_demo.py

```

### 3. Basic Usage

```python
from src.aip_hjs.verifier import AIPJudgmentVerifier

# Initialize the verifier (Sidecar mode)
verifier = AIPJudgmentVerifier()

# Define the operation context
context = {
    "operation": "write",
    "resource": "prod-db/settings",
    "risk_level": "high",
    "policy_uri": "https://policy.hjs-spec.org/v1/security.hjs",
    "actor_id": "agent-88"
}

# Issue a cryptographically signed receipt
receipt = verifier.issue_judgment("aat_jti_550e8400", context)
print(f"Issued Receipt ID: {receipt['receipt_id']}")

```

## 📜 Specification Compliance

This implementation is aligned with the following standards:

* **HJS Protocol**: `draft-wang-hjs-judgment-event-00`
* **Identifier**: **RFC 9562** (UUIDv7)
* **Security**: **RFC 8032** (Ed25519)
* **Public Key Format**: **RFC 7517** (JWK)

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details. This license is chosen for its industry-wide compatibility and explicit patent grant.

---
