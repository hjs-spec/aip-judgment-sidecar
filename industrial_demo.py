from aip_hjs.verifier import AIPJudgmentVerifier
from aip_hjs.models import OperationType, RiskLevel
import json

def run_demo():
    # 1. 初始化验证器 (模拟 sidecar 启动)
    verifier = AIPJudgmentVerifier()
    print(f"🚀 HJS Sidecar Started.")
    print(f"🔑 Public Key (JWK): {json.dumps(verifier.get_verifier_public_key(), indent=2)}")

    # 2. 模拟 AIP 拦截到的工具调用上下文
    # 假设 Agent 想要修改生产数据库配置
    mock_context = {
        "operation": OperationType.WRITE,
        "resource": "db://prod-cluster-01/config",
        "timestamp": "2026-03-05T21:00:00Z",
        "risk_level": RiskLevel.HIGH,
        "policy_uri": "https://specs.hjs.org/policies/v1/production-safety.hjs",
        "policy_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "actor_id": "agent-7749",
        "metadata": {"request_id": "req-999"}
    }

    # 3. 模拟 AAT 的唯一标识 (AAT JTI)
    aat_jti = "aat_urn:uuid:550e8400-e29b-41d4-a716-446655440000"

    print("\n⚖️  Processing Responsibility Judgment...")
    
    # 4. 发放判定收据
    receipt = verifier.issue_judgment(aat_jti, mock_context)

    print("\n✅ Judgment Receipt Issued (UUIDv7 Based):")
    print(receipt.to_json())

    print("\n🔍 Audit Insight:")
    print(f"- The Receipt ID '{receipt.receipt_id}' is chronologically sortable.")
    print(f"- The signature ensures the AIP Proxy cannot deny this judgment.")

if __name__ == "__main__":
    run_demo()
