"""Ingestion envelope and processor boundary."""

from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from navis_common.auth import Principal


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")
    namespace: str = Field(min_length=1, max_length=255)
    external_device_id: str = Field(min_length=1, max_length=255)


class DeviceMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")
    navis_device_id: UUID | None = None


class Adapter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    input_format: str = Field(min_length=1, max_length=255)
    format_version: str = Field(min_length=1, max_length=255)


class Ingestion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Source
    device_mapping: DeviceMapping | None = None
    adapter: Adapter
    data_type: Literal["device", "interface", "route", "policy", "nat", "neighbor", "mac", "topology", "security_zone"]
    collected_at: datetime
    completeness: Literal["complete", "partial", "unknown"]
    payload: dict[str, Any]

    @field_validator("collected_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")
        return value


class IngestionProcessor(Protocol):
    def submit(self, submission: Ingestion, principal: Principal) -> dict[str, Any]:
        """Authorize source/device scope, persist, then queue approved processing."""


class UnavailableProcessor:
    def submit(self, submission: Ingestion, principal: Principal) -> dict[str, Any]:
        raise NotImplementedError("Ingestion storage and processing are not configured")


class PostgresIngestionProcessor:
    """Persist a submission after explicit consumer/source authorization.

    Identity resolution, device authorization and adapter execution are deferred;
    a claimed device UUID is stored as an untrusted claim only.
    """

    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def submit(self, submission: Ingestion, principal: Principal) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        if not principal.issuer:
            raise PermissionError("Issuer is required")
        submission_id = uuid4()
        with self.connection_factory() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """SELECT s.id FROM navis.source_system s
                       JOIN navis.consumer_data_scope ds ON ds.source_system_id = s.id
                       JOIN navis.api_consumer c ON c.id = ds.api_consumer_id
                       WHERE s.namespace = %s AND c.issuer = %s AND c.subject_or_client_id = %s
                         AND c.status = 'active' AND ds.permissions @> %s::jsonb""",
                    (submission.source.namespace, principal.issuer, principal.subject, Jsonb(["inventory:write"])),
                )
                source = cursor.fetchone()
                if source is None:
                    raise PermissionError("Source access denied")
                # A claimed device is a claim only, never an authorization or association.
                # The FK validates existence; mapping approval happens separately.
                claimed_id = submission.device_mapping.navis_device_id if submission.device_mapping else None
                cursor.execute(
                    """INSERT INTO navis.ingestion_submission
                       (id, source_system_id, external_device_id, claimed_device_id,
                        adapter_name, input_format, format_version, data_type, collected_at,
                        completeness, payload, submitted_by, status)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending_identity')""",
                    (submission_id, source[0], submission.source.external_device_id, claimed_id,
                     submission.adapter.name, submission.adapter.input_format, submission.adapter.format_version,
                     submission.data_type, submission.collected_at, submission.completeness,
                     Jsonb(submission.payload), principal.subject),
                )
        return {"ingestion_id": str(submission_id), "status": "pending_identity"}
