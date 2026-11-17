"""Trace request and fail-closed processing boundary."""
from typing import Protocol
from uuid import UUID, uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from navis_common.trace import Flow, expand_flows


class TraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph_build_id: UUID | None = None
    topology_name: str | None = Field(default=None, min_length=1, max_length=255)
    topology_version_id: UUID | None = None
    namespace: str | None = Field(default=None, min_length=1, max_length=255)
    caller_session_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=16000)
    destination: str = Field(min_length=1, max_length=16000)
    protocol: str = Field(min_length=1, max_length=16)
    destination_port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    application: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("topology_name")
    @classmethod
    def topology_nonblank(cls, value):
        if value is not None:
            value = value.strip()
            if not value:
                raise ValueError("topology_name must not be blank")
            if '/' in value or any(ord(char) < 32 for char in value):
                raise ValueError("topology_name cannot contain slashes or control characters")
        return value

    @model_validator(mode="after")
    def one_topology_selector(self):
        if self.graph_build_id is not None and self.topology_name is not None:
            raise ValueError("use topology_name or graph_build_id, not both")
        if self.topology_version_id is not None and self.topology_name is None:
            raise ValueError("topology_version_id requires topology_name")
        return self

    def flows(self) -> list[Flow]:
        return expand_flows(self.source, self.destination, self.protocol, self.destination_port, application=self.application)


class TraceProcessor(Protocol):
    def trace(self, request: TraceRequest, flows: list[Flow], principal) -> dict:
        """Authorize dataset and return evidence-based trace results."""


class UnavailableTraceProcessor:
    def trace(self, request: TraceRequest, flows: list[Flow], principal) -> dict:
        raise NotImplementedError("Trace analysis is not configured")
