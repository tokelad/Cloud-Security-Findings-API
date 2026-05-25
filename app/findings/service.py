from app.findings.schemas import SecurityFinding
from glom import Coalesce, glom


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}

STATUS_MAP = {
    "open": "open",
    "in_progress": "in_progress",
    "in-progress": "in_progress",
    "resolved": "resolved",
    "closed": "resolved",
    "dismissed": "dismissed",
    "rejected": "dismissed",
    "snoozed": "snoozed",
}

CLOUD_MAP = {
    "aws": "aws",
    "azure": "azure",
    "gcp": "gcp",
    "google_cloud": "gcp",
    "alibaba_cloud": "unknown",
}

CATEGORY_MAP = {
    "vulnerability": "vulnerability",
    "vulnerabilities": "vulnerability",
    "misconfiguration": "misconfiguration",
    "misconfigurations": "misconfiguration",
    "identity_risk": "identity_risk",
    "identity risks": "identity_risk",
    "identity risk": "identity_risk",
    "network_exposure": "network_exposure",
    "network exposure": "network_exposure",
    "malware": "malware",
    "secret": "secret",
    "secrets": "secret",
    "data_risk": "data_risk",
    "data risk": "data_risk",
    "compliance": "compliance",
    "attack_path": "attack_path",
    "attack path": "attack_path",
}


def map_severity(value: str | None) -> str:
    if not value:
        return "unknown"
    return SEVERITY_MAP.get(value.strip().lower(), "unknown")


def map_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return STATUS_MAP.get(value.strip().lower(), "unknown")


def map_cloud(value: str | None) -> str:
    if not value:
        return "unknown"
    normalized = value.strip().lower().replace(" ", "_")
    return CLOUD_MAP.get(normalized, normalized)


def map_category(value: str | None) -> str:
    if not value:
        return "other"
    normalized = value.strip().lower().replace("-", "_")
    return CATEGORY_MAP.get(normalized, CATEGORY_MAP.get(normalized.replace("_", " "), "other"))


def join_remediation(*values: object) -> str | None:
    parts: list[str] = []

    for value in values:
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
        elif isinstance(value, list):
            parts.extend(str(item).strip() for item in value if str(item).strip())

    if not parts:
        return None

    return "\n".join(dict.fromkeys(parts))


def first_item(value: list[str] | None) -> str | None:
    if not value:
        return None
    return value[0]


def pick_region(value: object) -> str | None:
    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


WIZ_ISSUES_SPEC = {
    "provider_finding_id": Coalesce("id", default=None),

    "title": Coalesce(
        "control.name",
        "name",
        default="Untitled Wiz finding",
    ),

    "description": Coalesce(
        "control.description",
        default=None,
    ),

    "remediation": Coalesce(
        "control.resolutionRecommendation",
        default=None,
    ),

    "severity": (
        Coalesce("severity", default=None),
        map_severity,
    ),

    "status": (
        Coalesce("status", default=None),
        map_status,
    ),

    "asset": {
        "provider_asset_id": Coalesce("entitySnapshot.id", default=None),
        "name": Coalesce("entitySnapshot.name", default=None),
        "type": Coalesce("entitySnapshot.type", default=None),
        "cloud": (
            Coalesce("entitySnapshot.cloudPlatform", default=None),
            map_cloud,
        ),
        "region": Coalesce("entitySnapshot.region", default=None),
    },

    "ownership": {
        "project_id": Coalesce("projects.0.id", default=None),
        "project_name": Coalesce("projects.0.name", default=None),
    },

    "timestamps": {
        "created_at": Coalesce("createdAt", default=None),
        "updated_at": Coalesce("updatedAt", default=None),
        "resolved_at": Coalesce("resolvedAt", default=None),
    },
}

ORCA_ALERT_EVENT_SPEC = {
    "provider_finding_id": Coalesce("data.alert_id", "data.id", default=None),
    "provider_url": Coalesce("data.alert_ui_link", default=None),
    "category": (
        Coalesce("data.alert_category", "data.type", default=None),
        map_category,
    ),
    "title": Coalesce(
        "data.type",
        "data.alert_category",
        "data.asset_name",
        default="Untitled Orca alert",
    ),
    "description": Coalesce("data.description", "data.details", default=None),
    "remediation": lambda target: join_remediation(
        glom(target, Coalesce("data.recommendation", default=None)),
        glom(target, Coalesce("data.remediation_cli", default=None)),
        glom(target, Coalesce("data.remediation_console", default=None)),
    ),
    "severity": (
        Coalesce("data.risk_level", default=None),
        map_severity,
    ),
    "status": (
        Coalesce("data.status", default=None),
        map_status,
    ),
    "risk_score": Coalesce("data.orca_score", default=None),
    "asset": {
        "provider_asset_id": Coalesce("data.asset_unique_id", default=None),
        "name": Coalesce("data.asset_name", default=None),
        "type": Coalesce("data.asset_type", "data.asset_category", default=None),
        "cloud": (
            Coalesce("data.cloud_provider", default=None),
            map_cloud,
        ),
        "account_id": Coalesce("data.account_id", default=None),
        "account_name": Coalesce("data.account_name", default=None),
        "region": (
            Coalesce("data.asset_regions", default=None),
            pick_region,
        ),
        "tags": Coalesce("data.asset_tags", "data.custom_tags", default=None),
    },
    "timestamps": {
        "created_at": Coalesce("data.created_at", default=None),
        "updated_at": Coalesce("data.last_updated", default=None),
        "last_seen_at": Coalesce("data.last_seen", default=None),
        "resolved_at": Coalesce("data.closed_time", default=None),
    },
    "vulnerability": {
        "cve": (
            Coalesce("data.cve_list", default=None),
            first_item,
        ),
        "cvss": Coalesce("data.max_cvss_score", default=None),
        "package_name": Coalesce("data.source", default=None),
    },
    "compliance": {
        "framework": (
            Coalesce("data.related_compliances", default=None),
            first_item,
        ),
    },
}

ORCA_ALERT_LEGACY_SPEC = {
    "provider_finding_id": Coalesce("state.alert_id", "rule_id", default=None),
    "category": (
        Coalesce("category", "type", "type_string", default=None),
        map_category,
    ),
    "title": Coalesce(
        "type_string",
        "type",
        "category",
        default="Untitled Orca alert",
    ),
    "description": Coalesce("description", "details", default=None),
    "remediation": lambda target: join_remediation(
        glom(target, Coalesce("recommendation", default=None)),
        glom(target, Coalesce("remediation_cli", default=None)),
    ),
    "severity": (
        Coalesce("state.severity", "state.risk_level", default=None),
        map_severity,
    ),
    "status": (
        Coalesce("state.status", "configuration.user_status", default=None),
        map_status,
    ),
    "risk_score": Coalesce("state.orca_score", "state.score", "configuration.user_score", default=None),
    "asset": {
        "provider_asset_id": Coalesce("asset_unique_id", default=None),
        "name": Coalesce("asset_name", default=None),
        "type": Coalesce("asset_type", "asset_type_string", "asset_category", default=None),
        "cloud": (
            Coalesce("cloud_provider", "cloud_account_type", default=None),
            map_cloud,
        ),
        "account_id": Coalesce("cloud_account_id", "cloud_provider_id", default=None),
        "account_name": Coalesce("account_name", default=None),
        "region": (
            Coalesce("asset_regions", default=None),
            pick_region,
        ),
        "tags": Coalesce("data.asset_tags", default=None),
    },
    "timestamps": {
        "created_at": Coalesce("state.created_at", default=None),
        "updated_at": Coalesce("state.last_updated", default=None),
        "last_seen_at": Coalesce("state.last_seen", default=None),
        "resolved_at": Coalesce("state.closed_time", default=None),
    },
    "vulnerability": {
        "cve": (
            Coalesce("cve_list", default=None),
            first_item,
        ),
        "cvss": Coalesce("max_cvss_score", default=None),
        "package_name": Coalesce("source", default=None),
    },
    "compliance": {
        "framework": (
            Coalesce("related_compliances", default=None),
            first_item,
        ),
    },
}


class NormalizePayloads:
    @staticmethod
    def _build_finding(provider: str, normalized: dict, raw: dict) -> SecurityFinding:
        provider_finding_id = normalized.get("provider_finding_id")

        if not provider_finding_id:
            raise ValueError(f"{provider.capitalize()} payload does not contain required finding id")

        return SecurityFinding(
            id=f"{provider}:{provider_finding_id}",
            provider=provider,
            category=normalized.pop("category"),
            dedupe_key=f"{provider}:{provider_finding_id}",
            raw=raw,
            **normalized,
        )

    @staticmethod
    def normalize_wiz_issue(issue: dict) -> SecurityFinding:
        normalized = glom(issue, WIZ_ISSUES_SPEC)
        normalized["category"] = "misconfiguration"
        return NormalizePayloads._build_finding("wiz", normalized, issue)

    @staticmethod
    def normalize_orca_alert_event(alert: dict) -> SecurityFinding:
        normalized = glom(alert, ORCA_ALERT_EVENT_SPEC)
        return NormalizePayloads._build_finding("orca", normalized, alert)

    @staticmethod
    def normalize_orca_alert(alert: dict) -> SecurityFinding:
        normalized = glom(alert, ORCA_ALERT_LEGACY_SPEC)
        return NormalizePayloads._build_finding("orca", normalized, alert)
