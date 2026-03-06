# AIP Judgment Sidecar (HJS Reference Implementation)

This repository provides an industrial-grade, **non-intrusive** implementation of the **Heterogeneous Judgment Service (HJS)** for the **AI Proxy (AIP)** ecosystem.

It serves as a "Responsibility Anchor," allowing AIP to delegate complex policy judgments to a specialized sidecar without modifying its core identity or access control logic.

---

## 🌟 Key Features

* **Chronological Traceability**: Uses **UUIDv7 (RFC 9562)** for receipt IDs, enabling high-performance database indexing and time-ordered audit trails.
* **Cryptographic Accountability**: Implements **Ed25519 (EdDSA)** asymmetric signatures for multi-channel verification and non-repudiation.
* **Structured Context Binding**: Ensures every judgment is cryptographically tied to the specific operation context (resource, risk level, and policy hash).
* **Zero-Intrusion Architecture**: Designed to run as a sidecar, integrating with AIP via standard JSON-based verification requests.

---

## 🏗️ Architecture

In the AIP-HJS integrated flow, the Sidecar acts as a specialized **"Judicial Branch"**:

1. **AIP Proxy** intercepts a sensitive tool call from an AI Agent.
2. **AIP Proxy** forwards the Agent's **AAT** (Accountability Attachment Token) and the **Operation Context** to the HJS Sidecar.
3. **HJS Sidecar** evaluates the request against the anchored policy and generates a judgment.
4. **HJS Sidecar** issues a signed **HJS Receipt** (UUIDv7 based).
5. **AIP Proxy** attaches the receipt to the final execution request for downstream auditing.

---

## 📊 Sample Output (HJS Receipt)

When running `industrial_demo.py`, the HJS Sidecar generates a cryptographically bound receipt. The `receipt_id` encodes the precise time of judgment:

```json
{
  "version": "hjs-v1",
  "receipt_id": "hjs_018e154a-5678-7123-8123-abcdef123456",
  "aat_jti": "aat_urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "judgment": "approved",
  "issued_at": "2026-03-05T21:00:00Z",
  "verifier": "hjs-sidecar-v1-stable",
  "context_summary": {
    "op": "write",
    "res": "production/config.json",
    "policy": "https://hjs-spec.org/policy/safety-v1.hjs"
  },
  "signature": "ed25519:6gH8...[truncated]...zP9q"
}

```

> **Note**: The `receipt_id` starts with `018e15...`, a characteristic of **UUIDv7** indicating the timestamp. This ensures all judgments are natively sortable by the time of issuance.

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/hjs-spec/aip-judgment-sidecar.git
cd aip-judgment-sidecar

# Install dependencies
pip install -r requirements.txt

```

### 2. Run  Demo

```bash
python industrial_demo.py

```

### 3. Basic Integration

```python
from src.aip_hjs.verifier import AIPJudgmentVerifier

# Initialize the verifier
verifier = AIPJudgmentVerifier()

# Define the operation context from AIP
context = {
    "operation": "write",
    "resource": "prod-db/settings",
    "risk_level": "high",
    "policy_uri": "https://policy.hjs-spec.org/v1/security.hjs",
    "actor_id": "agent-88"
}

# Issue a cryptographically signed HJS receipt
receipt = verifier.issue_judgment("aat_jti_550e8400", context)

```

---

## 📜 Specification Compliance

This implementation is strictly aligned with the following standards:

* **HJS Protocol**: [draft-wang-hjs-judgment-event-00](https://datatracker.ietf.org/doc/draft-wang-hjs-judgment-event/)
* **Identifier**: **RFC 9562** (UUIDv7)
* **Security**: **RFC 8032** (Ed25519)
* **Public Key Format**: **RFC 7517** (JWK)

---

## 📄 License

This project is licensed under the **Apache License 2.0**. 

---

**Current Status**: 🟢 Functional Reference Implementation. 

---
