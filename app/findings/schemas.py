from pydantic import BaseModel, Field
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class Provider(str, Enum):
    WIZ = "wiz"
    ORCA = "orca"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    SNOOZED = "snoozed"
    UNKNOWN = "unknown"


class FindingCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    IDENTITY_RISK = "identity_risk"
    NETWORK_EXPOSURE = "network_exposure"
    MALWARE = "malware"
    SECRET = "secret"
    DATA_RISK = "data_risk"
    COMPLIANCE = "compliance"
    ATTACK_PATH = "attack_path"
    OTHER = "other"


class Asset(BaseModel):
    provider_asset_id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    cloud: Optional[str] = "unknown"
    account_id: Optional[str] = None
    account_name: Optional[str] = None
    region: Optional[str] = None
    tags: Optional[dict[str, str]] = None


class Vulnerability(BaseModel):
    cve: Optional[str] = None
    cvss: Optional[float] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    exploitable: Optional[bool] = None
    exploit_available: Optional[bool] = None


class Compliance(BaseModel):
    framework: Optional[str] = None
    control_id: Optional[str] = None
    control_name: Optional[str] = None


class Ownership(BaseModel):
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    team: Optional[str] = None
    owner: Optional[str] = None


class FindingTimestamps(BaseModel):
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None


class SecurityFinding(BaseModel):
    id: str
    provider: Provider
    provider_finding_id: str
    provider_url: Optional[str] = None

    category: FindingCategory

    title: str
    description: Optional[str] = None
    remediation: Optional[str] = None

    severity: Severity = Severity.UNKNOWN
    status: FindingStatus = FindingStatus.UNKNOWN

    risk_score: Optional[float] = None

    asset: Asset = Field(default_factory=Asset)
    vulnerability: Optional[Vulnerability] = None
    compliance: Optional[Compliance] = None
    ownership: Optional[Ownership] = None

    timestamps: FindingTimestamps = Field(default_factory=FindingTimestamps)

    dedupe_key: str
    raw: Any
    ingested_at: datetime = Field(default_factory=datetime.utcnow)