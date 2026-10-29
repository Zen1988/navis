"""HTTP boundary for Navis. Persistence and authentication are fail-closed."""

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from pathlib import Path
import os
from functools import partial

from navis_common.auth import DenyAllVerifier, Principal
from .ingestion import Ingestion, UnavailableProcessor
from .trace import TraceRequest, UnavailableTraceProcessor

app = FastAPI(title="Navis API", version="0.1.0")
app.state.token_verifier = DenyAllVerifier()
app.state.ingestion_processor = UnavailableProcessor()
app.state.graph_reader = None
app.state.trace_processor = UnavailableTraceProcessor()
app.state.trace_sessions = None
bearer = HTTPBearer(auto_error=False)


@app.on_event("startup")
def configure_test_services():
    """Opt-in local test configuration; absence leaves the service fail-closed."""
    dsn = os.environ.get("NAVIS_DATABASE_URL")
    token = os.environ.get("NAVIS_LOCAL_TOKEN")
    if dsn:
        import psycopg
        from .ingestion import PostgresIngestionProcessor
        from .trace_postgres import PostgresTraceProcessor
        from .trace_session import PostgresTraceSessions
        from .graph_response import get_graph
        factory = lambda: psycopg.connect(dsn)
        app.state.ingestion_processor = PostgresIngestionProcessor(factory)
        app.state.trace_processor = PostgresTraceProcessor(factory)
        app.state.trace_sessions = PostgresTraceSessions(factory)
        app.state.graph_reader = partial(get_graph, factory)
    if token:
        from navis_common.local_auth import LocalTokenVerifier
        scopes = frozenset(os.environ.get("NAVIS_LOCAL_SCOPES", "").split())
        app.state.token_verifier = LocalTokenVerifier(token, Principal(
            subject=os.environ.get("NAVIS_LOCAL_SUBJECT", "local-test"),
            issuer=os.environ.get("NAVIS_LOCAL_ISSUER", "navis-local"), scopes=scopes))


@app.get("/", include_in_schema=False)
def test_console():
    return FileResponse(Path(__file__).resolve().parents[2] / "web" / "index.html")


def require_scope(scope: str):
    def authorize(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
        if credentials is None:
            raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
        principal = request.app.state.token_verifier.verify(credentials.credentials)
        if principal is None:
            raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
        if scope not in principal.scopes:
            raise HTTPException(status_code=403, detail="Insufficient scope")
        return principal
    return authorize


@app.get("/health/live")
def liveness():
    return {"status": "ok"}


@app.get("/health/ready")
def readiness(request: Request):
    # Readiness also requires the DB to be reachable; analysis remains partial.
    if isinstance(request.app.state.token_verifier, DenyAllVerifier) or isinstance(request.app.state.ingestion_processor, UnavailableProcessor):
        raise HTTPException(status_code=503, detail="Authentication and database are not configured")
    try:
        with request.app.state.ingestion_processor.connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM navis.ingestion_submission LIMIT 1")
    except Exception:
        raise HTTPException(status_code=503, detail="Database or schema is unavailable")
    return {"status": "ready"}


@app.get("/v1/applications")
def list_applications(principal: Principal = Depends(require_scope("application:read"))):
    raise HTTPException(status_code=503, detail="Application storage is not configured")


@app.post("/v1/ingestions", status_code=202)
def submit_ingestion(submission: Ingestion, request: Request,
                     principal: Principal = Depends(require_scope("inventory:write"))):
    try:
        return request.app.state.ingestion_processor.submit(submission, principal)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Source access denied")
    except NotImplementedError:
        raise HTTPException(status_code=503, detail="Ingestion processing is not configured")


@app.get("/v1/graph-builds/{build_id}/graph")
def read_graph(build_id: str, request: Request, principal: Principal = Depends(require_scope("graph:read"))):
    from uuid import UUID
    try:
        parsed_id = UUID(build_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid graph build ID")
    if request.app.state.graph_reader is None:
        raise HTTPException(status_code=503, detail="Graph reader is not configured")
    try:
        return request.app.state.graph_reader(parsed_id, principal)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Graph access denied")
    except LookupError:
        raise HTTPException(status_code=404, detail="Graph build not found")
    except ValueError:
        raise HTTPException(status_code=409, detail="Graph build is not completed")


@app.post("/v1/traces")
def trace_path(submission: TraceRequest, request: Request,
               principal: Principal = Depends(require_scope("analysis:run"))):
    try:
        flows = submission.flows()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        result = request.app.state.trace_processor.trace(submission, flows, principal)
        if request.app.state.trace_sessions is None:
            raise HTTPException(status_code=503, detail="Trace session storage is not configured")
        session_id = request.app.state.trace_sessions.save(principal, submission.caller_session_id, submission.graph_build_id, submission.model_dump(mode="json"), result)
        return {"code": "TRACE_RESULT_READY", "caller_session_id": submission.caller_session_id, "trace_session_id": str(session_id), **result}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Dataset access denied")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except NotImplementedError:
        raise HTTPException(status_code=503, detail="Trace analysis is not configured")


@app.get("/v1/trace-sessions/{caller_session_id}/recommendations")
def trace_recommendations(caller_session_id: str, request: Request,
                          principal: Principal = Depends(require_scope("analysis:read"))):
    if request.app.state.trace_sessions is None:
        raise HTTPException(status_code=503, detail="Trace session storage is not configured")
    try:
        return request.app.state.trace_sessions.recommendations(principal, caller_session_id)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Session access denied")
    except LookupError:
        raise HTTPException(status_code=404, detail="Session not found or expired")
