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
    """
    Standardized JEP Judgment Context.
    Ensures that every responsibility judgment is bound to a consistent set of metadata.
    """
    operation: str           # Operation type (OperationType)
    resource: str            # Target resource identifier
    timestamp: str           # ISO 8601 format
    risk_level: str          # Risk level (RiskLevel)
    policy_uri: str          # URI of the policy used for judgment
    policy_hash: str         # Cryptographic hash of the policy document
    actor_id: str            # Executor ID (typically mapping to AAT's 'sub')
    metadata: Dict[str, Any] # Additional JEP-specific extensions
