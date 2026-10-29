"""Trace request and fail-closed processing boundary."""
from typing import Protocol
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field
from navis_common.trace import Flow, expand_flows


class TraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph_build_id: UUID
    caller_session_id: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=16000)
    destination: str = Field(min_length=1, max_length=16000)
    protocol: str = Field(min_length=1, max_length=16)
    destination_port: int | None = Field(default=None, ge=0, le=65535, strict=True)
    source_port: int | None = Field(default=None, ge=0, le=65535, strict=True)

    def flows(self) -> list[Flow]:
        return expand_flows(self.source, self.destination, self.protocol, self.destination_port)


class TraceProcessor(Protocol):
    def trace(self, request: TraceRequest, flows: list[Flow], principal) -> dict:
        """Authorize dataset and return evidence-based trace results."""


class UnavailableTraceProcessor:
    def trace(self, request: TraceRequest, flows: list[Flow], principal) -> dict:
        raise NotImplementedError("Trace analysis is not configured")
