from typing import TypedDict, Optional, Dict, Any
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class OperationType(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"

class JudgmentContext(TypedDict):
    """标准化的责任判定上下文"""
    operation: str          # 操作类型 (OperationType)
    resource: str           # 操作资源标识
    timestamp: str          # ISO 8601 格式
    risk_level: str         # 风险等级
    policy_uri: str         # 判定依据的策略 URI
    policy_hash: str        # 策略文档哈希
    actor_id: str           # 执行者 ID (通常对应 AAT 的 sub)
    metadata: Dict[str, Any]
