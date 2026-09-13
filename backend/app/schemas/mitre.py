"""ATT&CK coverage API schemas (spec §23's MITRE ATT&CK screen)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TacticPublic(BaseModel):
    id: str
    name: str
    shortname: str
    url: str | None


class TechniquePublic(BaseModel):
    id: str
    name: str
    is_subtechnique: bool
    parent_id: str | None
    tactics: list[str]
    platforms: list[str]
    is_deprecated: bool
    is_revoked: bool
    url: str | None


class TacticCoveragePublic(BaseModel):
    tactic_id: str
    name: str
    shortname: str
    total: int
    covered: int
    partial: int
    coverage_rate: float


class TechniqueCoveragePublic(BaseModel):
    technique_id: str
    name: str
    is_subtechnique: bool
    parent_id: str | None
    tactics: list[str]
    # covered | partial | uncovered — "partial" means a sub-technique is
    # covered but the parent as a whole is not.
    status: str
    rule_keys: list[str]
    detection_count: int


class CoveragePublic(BaseModel):
    attack_version: str | None
    imported_at: datetime | None
    catalog_is_stale: bool
    total_techniques: int
    covered_techniques: int
    partially_covered_techniques: int
    coverage_rate: float
    detection_window_days: int
    tactics: list[TacticCoveragePublic]
    techniques: list[TechniqueCoveragePublic]
    # Techniques a rule claims that the imported catalog does not contain:
    # a typo or a rule written against a newer ATT&CK than the one imported.
    unknown_technique_claims: dict[str, list[str]]


class DetectionSummary(BaseModel):
    detection_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str | None = None
    risk_score: int | None = None
    risk_bucket: str | None = None
    mitre_attack: list[str] = Field(default_factory=list)
    entity_summary: str | None = None
    matched_at: str | None = None
    event_ids: list[str] = Field(default_factory=list)


class TechniqueDetail(BaseModel):
    technique: TechniquePublic
    status: str
    rule_keys: list[str]
    detection_count: int
    recent_detections: list[DetectionSummary]


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # A URL (fetched through the egress guard) or a filename in the
    # intelligence drop directory. Defaults to the configured source.
    source: str | None = Field(default=None, max_length=500)


class ImportResult(BaseModel):
    source: str
    attack_version: str | None
    tactics_imported: int
    techniques_imported: int
    objects_rejected: int
    rules_mapped: int
    mappings_removed: int
