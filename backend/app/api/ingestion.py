"""Ingestion gateway routes (spec §5/§22, ARCHITECTURE.md §5).

Two distinct authentication schemes meet here and must not be confused:

- **Collectors** authenticate with an `X-API-Key` collector key and may only
  push events. They hold no RBAC permissions and can read nothing.
- **Humans** authenticate with a JWT and need `api_key:write` to mint a
  collector key.
"""

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.audit.service import record_audit_event
from app.auth.dependencies import AuthContext, require_permission
from app.collectors.rest import RestCollector
from app.core.eventbus import get_event_bus
from app.core.redis import get_redis
from app.models.identity import ApiKey
from app.services import api_keys as api_key_service
from app.services.ingestion import IngestionService, IngestOutcome

router = APIRouter(tags=["ingestion"])

_rest_collector = RestCollector(collector_id="rest-gateway")


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class CreateApiKeyResponse(BaseModel):
    id: str
    name: str
    api_key: str = Field(
        description="Shown exactly once — it is stored only as a hash and cannot be recovered."
    )


class IngestResponse(BaseModel):
    outcome: str
    message_id: str | None = None
    reason: str | None = None


async def get_collector_key(x_api_key: str | None = Header(default=None)) -> ApiKey:
    if x_api_key is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing X-API-Key header")
    api_key = await api_key_service.resolve_collector_key(x_api_key)
    if api_key is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or revoked API key")
    return api_key


def get_ingestion_service() -> IngestionService:
    return IngestionService(bus=get_event_bus(), redis=get_redis())


@router.post("/api-keys", response_model=CreateApiKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: CreateApiKeyRequest,
    ctx: AuthContext = Depends(require_permission("api_key", "write")),
) -> CreateApiKeyResponse:
    plaintext, api_key = await api_key_service.create_collector_key(
        tenant_id=ctx.user.tenant_id, name=payload.name, created_by=ctx.user.id
    )
    await record_audit_event(
        ctx.db,
        tenant_id=ctx.user.tenant_id,
        actor_id=ctx.user.id,
        action="CREATE_API_KEY",
        object_type="api_key",
        object_id=str(api_key.id),
        result="success",
        after_state={"name": payload.name, "is_collector_key": True},
    )
    await ctx.db.commit()
    return CreateApiKeyResponse(id=str(api_key.id), name=api_key.name, api_key=plaintext)


@router.post("/ingest/events", response_model=IngestResponse)
async def ingest_event(
    request: Request,
    response: Response,
    api_key: ApiKey = Depends(get_collector_key),
    ingestion: IngestionService = Depends(get_ingestion_service),
) -> IngestResponse:
    """Accepts one raw event as an opaque request body. The gateway does not
    parse or validate the payload's *content* — that is the parsing stage's
    job in Phase 4, and doing it here would mean rejecting events this SIEM
    should be capturing precisely because they are malformed."""
    raw_payload = await request.body()

    event = _rest_collector.build_event(
        tenant_id=uuid.UUID(str(api_key.tenant_id)),
        raw_payload=raw_payload,
        source_ip=request.client.host if request.client else None,
    )
    result = await ingestion.ingest(event)

    if result.outcome is IngestOutcome.RATE_LIMITED:
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS
    elif result.outcome is IngestOutcome.DEAD_LETTERED:
        # 202: we accepted responsibility for the event (it is durably in the
        # dead-letter topic, recoverable and replayable) but it did not enter
        # the pipeline. Not a 4xx — the caller has nothing to fix by retrying.
        response.status_code = status.HTTP_202_ACCEPTED
    elif result.outcome is IngestOutcome.DROPPED:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    return IngestResponse(
        outcome=result.outcome.value, message_id=result.message_id, reason=result.reason
    )
