"""Rule lifecycle: install, read, edit, version, enable/disable, except.

Every mutation here does three things in one transaction — change the rule,
append its new version, write the audit entry — because a rule change that
is not recoverable and attributable is indistinguishable from sabotage after
the fact. Disabling a detection is one of the highest-value actions an
attacker with a foothold in the SIEM can take (THREAT_MODEL.md §3.4), and
the only defence that survives them having valid credentials is a record
they cannot edit: `detection_rule_versions` and `audit_logs` are both
append-only at the database level, not by convention here.

The parsed rule is always the authority for what gets stored. A caller
submits YAML; it is validated by the same loader the worker uses, and the
indexed columns are then written *from the parsed object*. There is no path
where the row says `severity: low` and the YAML the engine executes says
`critical`.
"""

import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core.config import get_settings
from app.detection.loader import RuleLoadError, load_rules, parse_rule, rule_to_yaml
from app.detection.schema import DetectionRule, RuleException, RuleStatus
from app.models.detection import DetectionRuleRecord, DetectionRuleVersion, RuleExceptionRecord

logger = logging.getLogger(__name__)


class RuleNotFound(LookupError):
    pass


class DuplicateRule(ValueError):
    pass


def _apply_rule_to_record(record: DetectionRuleRecord, rule: DetectionRule, yaml_text: str) -> None:
    """Indexed columns are always derived from the parsed rule — never taken
    from the request alongside the YAML, which is how the two drift."""
    record.rule_key = rule.rule_id
    record.name = rule.name
    record.description = rule.description
    record.severity = rule.severity.value
    record.confidence = rule.confidence
    record.risk_score = rule.risk_score
    record.status = rule.status.value
    record.rule_type = rule.rule_type
    record.definition_yaml = yaml_text
    record.false_positive_notes = rule.false_positive_notes
    record.investigation_steps = rule.investigation_steps
    record.references_urls = list(rule.references)
    record.mitre_techniques = list(rule.mitre_attack)
    record.author = rule.author


async def _get_by_key(
    db: AsyncSession, tenant_id: uuid.UUID, rule_key: str
) -> DetectionRuleRecord | None:
    stmt = select(DetectionRuleRecord).where(
        DetectionRuleRecord.tenant_id == tenant_id,
        DetectionRuleRecord.rule_key == rule_key,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def list_rules(db: AsyncSession, tenant_id: uuid.UUID) -> list[DetectionRuleRecord]:
    stmt = (
        select(DetectionRuleRecord)
        .where(DetectionRuleRecord.tenant_id == tenant_id)
        .order_by(DetectionRuleRecord.rule_key)
    )
    return list((await db.execute(stmt)).scalars())


async def get_rule(
    db: AsyncSession, tenant_id: uuid.UUID, rule_key: str
) -> DetectionRuleRecord:
    record = await _get_by_key(db, tenant_id, rule_key)
    if record is None:
        raise RuleNotFound(rule_key)
    return record


async def create_rule(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    yaml_text: str,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
    change_summary: str | None = None,
) -> DetectionRuleRecord:
    rule = parse_rule(yaml_text, origin="submitted rule")

    if await _get_by_key(db, tenant_id, rule.rule_id) is not None:
        raise DuplicateRule(rule.rule_id)

    record = DetectionRuleRecord(tenant_id=tenant_id, current_version=rule.version)
    _apply_rule_to_record(record, rule, yaml_text)
    db.add(record)
    await db.flush()

    db.add(
        DetectionRuleVersion(
            rule_id=record.id,
            tenant_id=tenant_id,
            version=record.current_version,
            definition_yaml=yaml_text,
            changed_by=actor_id,
            change_summary=change_summary or "initial version",
        )
    )
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_DETECTION_RULE",
        object_type="detection_rule",
        object_id=record.rule_key,
        after_state={"status": record.status, "version": record.current_version},
        result="success",
    )
    return record


async def update_rule(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    rule_key: str,
    yaml_text: str,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
    change_summary: str | None = None,
) -> DetectionRuleRecord:
    """Edits a rule and bumps its version. The submitted YAML must keep the
    same `rule_id`: renaming a rule in place would silently orphan every
    alert, exception and metric that references the old key."""
    record = await get_rule(db, tenant_id, rule_key)
    rule = parse_rule(yaml_text, origin=f"rule {rule_key}")
    if rule.rule_id != rule_key:
        raise RuleLoadError(
            f"rule_id cannot be changed on update ({rule_key} -> {rule.rule_id}); "
            "create a new rule instead"
        )

    before = {
        "status": record.status,
        "version": record.current_version,
        "definition_yaml": record.definition_yaml,
    }
    new_version = record.current_version + 1
    _apply_rule_to_record(record, rule, yaml_text)
    # The version in the database always wins over the one in the YAML: the
    # sequence has to be monotonic per rule, and an author who forgets to
    # bump it must not be able to overwrite history.
    record.current_version = new_version

    db.add(
        DetectionRuleVersion(
            rule_id=record.id,
            tenant_id=tenant_id,
            version=new_version,
            definition_yaml=yaml_text,
            changed_by=actor_id,
            change_summary=change_summary,
        )
    )
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="UPDATE_DETECTION_RULE",
        object_type="detection_rule",
        object_id=rule_key,
        before_state=before,
        after_state={
            "status": record.status,
            "version": new_version,
            "definition_yaml": yaml_text,
        },
        result="success",
    )
    return record


async def set_rule_status(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    rule_key: str,
    status: RuleStatus,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> DetectionRuleRecord:
    """Enable / disable / move to testing.

    Kept separate from `update_rule` on purpose: status changes are the ones
    that matter operationally (a disabled rule detects nothing), they are
    audited under their own action so they can be alerted on, and they do
    not create a new rule version because the rule's *content* did not
    change.
    """
    record = await get_rule(db, tenant_id, rule_key)
    before = record.status
    record.status = status.value
    record.definition_yaml = _yaml_with_status(record.definition_yaml, status)

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        # A distinct action per direction: "who disabled a detection, and
        # when" is a question worth being able to ask the audit log directly
        # rather than by parsing state diffs.
        action="DISABLE_DETECTION_RULE" if status is RuleStatus.DISABLED else
        "ENABLE_DETECTION_RULE",
        object_type="detection_rule",
        object_id=rule_key,
        before_state={"status": before},
        after_state={"status": record.status},
        result="success",
    )
    return record


def _yaml_with_status(yaml_text: str, status: RuleStatus) -> str:
    """Keeps the stored YAML consistent with the status column by
    round-tripping through the validated model, so the engine (which reads
    the YAML) and the API (which reads the column) can never disagree."""
    rule = parse_rule(yaml_text, origin="stored rule")
    return rule_to_yaml(rule.model_copy(update={"status": status}))


async def add_exception(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    rule_key: str,
    reason: str,
    conditions: dict[str, Any],
    expires_at: datetime | None,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> RuleExceptionRecord:
    record = await get_rule(db, tenant_id, rule_key)

    # Validated through the same schema the engine evaluates, so an
    # exception cannot be stored in a shape the engine will later choke on
    # (or, worse, silently ignore — an exception that does not apply looks
    # exactly like a rule that fires too much).
    exception = RuleException.model_validate(
        {
            "reason": reason,
            "conditions": conditions,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
    )

    row = RuleExceptionRecord(
        rule_id=record.id,
        tenant_id=tenant_id,
        match_criteria=exception.model_dump(mode="json", by_alias=True)["conditions"],
        reason=exception.reason,
        created_by=actor_id,
        expires_at=expires_at,
    )
    db.add(row)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_RULE_EXCEPTION",
        object_type="detection_rule",
        object_id=rule_key,
        after_state={
            "reason": reason,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
        result="success",
    )
    return row


async def list_exceptions(
    db: AsyncSession, tenant_id: uuid.UUID, rule_id: uuid.UUID
) -> list[RuleExceptionRecord]:
    stmt = select(RuleExceptionRecord).where(
        RuleExceptionRecord.tenant_id == tenant_id,
        RuleExceptionRecord.rule_id == rule_id,
    )
    return list((await db.execute(stmt)).scalars())


async def list_versions(
    db: AsyncSession, tenant_id: uuid.UUID, rule_id: uuid.UUID
) -> list[DetectionRuleVersion]:
    stmt = (
        select(DetectionRuleVersion)
        .where(
            DetectionRuleVersion.tenant_id == tenant_id,
            DetectionRuleVersion.rule_id == rule_id,
        )
        .order_by(DetectionRuleVersion.version.desc())
    )
    return list((await db.execute(stmt)).scalars())


def default_rules_directory() -> Path:
    return Path(get_settings().detection_rules_path)


async def install_default_rules(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None = None,
    directory: Path | None = None,
) -> list[str]:
    """Installs the shipped rule pack into a tenant. Idempotent, and
    deliberately non-destructive: a rule_key the tenant already has is
    skipped, never overwritten, because overwriting would silently undo
    local tuning — the exact behaviour that teaches a SOC to stop tuning."""
    directory = directory or default_rules_directory()
    result = load_rules(directory)
    for warning in result.warnings:
        logger.warning(warning)
    if not result.ok:
        raise RuleLoadError("; ".join(result.errors))

    installed: list[str] = []
    for rule in result.rules:
        if await _get_by_key(db, tenant_id, rule.rule_id) is not None:
            continue
        await create_rule(
            db,
            tenant_id=tenant_id,
            yaml_text=rule_to_yaml(rule),
            actor_id=actor_id,
            change_summary="installed from the default rule pack",
        )
        installed.append(rule.rule_id)

    logger.info(
        "default rule pack installed",
        extra={"tenant_id": str(tenant_id), "installed": len(installed)},
    )
    return installed


async def load_active_rules(db: AsyncSession, tenant_id: uuid.UUID) -> list[DetectionRule]:
    """What the detection workers execute: every non-disabled rule for the
    tenant, with its database-held exceptions merged in.

    A rule whose stored YAML no longer parses is skipped and logged loudly
    rather than taking the whole rule set down — one corrupted row must not
    stop the other rules from detecting.
    """
    stmt = select(DetectionRuleRecord).where(
        DetectionRuleRecord.tenant_id == tenant_id,
        DetectionRuleRecord.status != RuleStatus.DISABLED.value,
    )
    records = list((await db.execute(stmt)).scalars())

    rules: list[DetectionRule] = []
    for record in records:
        try:
            rule = parse_rule(record.definition_yaml, origin=f"rule {record.rule_key}")
        except RuleLoadError:
            logger.exception("stored rule failed to parse and was skipped")
            continue

        exceptions = await list_exceptions(db, tenant_id, record.id)
        merged = rule.model_copy(
            update={
                # The column is authoritative for status: enable/disable is
                # the one change that must take effect without a rule edit.
                "status": RuleStatus(record.status),
                "version": record.current_version,
                "exceptions": [*rule.exceptions, *_as_schema_exceptions(exceptions)],
            }
        )
        rules.append(merged)
    return rules


def _as_schema_exceptions(rows: list[RuleExceptionRecord]) -> list[RuleException]:
    exceptions: list[RuleException] = []
    for row in rows:
        if row.expires_at is not None and row.expires_at <= datetime.now(UTC):
            # Expired exceptions are simply not loaded: coverage comes back
            # by itself, which is the whole point of requiring an expiry.
            continue
        exceptions.append(
            RuleException.model_validate(
                {
                    "reason": row.reason,
                    "conditions": row.match_criteria,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                }
            )
        )
    return exceptions
