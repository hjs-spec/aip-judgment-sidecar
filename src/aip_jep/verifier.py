import json
from datetime import datetime
from typing import Optional
from .crypto import generate_uuid7, JEPAsymmetricSigner, compute_content_hash
from .models import JudgmentContext

class JEPReceipt:
    """
    JEP 判定收据实体
    """
    def __init__(self, data: dict):
        self.__dict__.update(data)
    
    def to_json(self):
        return json.dumps(self.__dict__, indent=2)

class AIPJudgmentVerifier:
    """
    AIP 专用判定验证器 (基于 JEP 协议实现)
    """
    def __init__(self, private_key_hex: Optional[str] = None):
        # 初始化 JEP 非对称签名器
        self.signer = JEPAsymmetricSigner(private_key_hex)
        self.verifier_id = "jep-sidecar-v1-stable"

    def issue_judgment(self, aat_jti: str, context: JudgmentContext) -> JEPReceipt:
        """
        基于 AAT 标识和上下文发放 JEP 责任收据
        """
        # 1. 生成基于时间的有序收据 ID (UUIDv7)，前缀改为 jep_
        receipt_id = f"jep_{generate_uuid7()}"
        
        # 2. 计算上下文绑定哈希 (防止收据被篡改用于其他操作)
        ctx_hash = compute_content_hash(context)
        
        # 3. 构建收据主体 (全面对齐 JEP 命名空间)
        receipt_body = {
            "version": "jep-v1",
            "receipt_id": receipt_id,
            "aat_jti": aat_jti,
            "judgment": "approved",  # 实际逻辑可在此扩展策略检查
            "ctx_hash": ctx_hash,
            "issued_at": datetime.utcnow().isoformat() + "Z",
            "verifier": self.verifier_id,
            "policy": {
                "uri": context.get("policy_uri"),
                "hash": context.get("policy_hash")
            }
        }
        
        # 4. 执行 Ed25519 签名 (JEP 多渠道可验证标准)
        signature = self.signer.sign_payload(receipt_body)
        receipt_body["signature"] = signature
        
        return JEPReceipt(receipt_body)

    def get_verifier_public_key(self):
        """导出 JEP 格式公钥供 AIP 或第三方审计使用"""
        return self.signer.get_public_key_jwk()
