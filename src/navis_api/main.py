"""HTTP boundary for Navis. Persistence and authentication are fail-closed."""

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from pathlib import Path
import os
from functools import partial
from uuid import uuid4

from navis_common.auth import DenyAllVerifier, Principal
from .ingestion import Ingestion, UnavailableProcessor
from .trace import TraceRequest, UnavailableTraceProcessor
from .nauth import issue_token
from .topology import TopologyRequest

app = FastAPI(title="Navis API", version="0.1.0")
app.state.token_verifier = DenyAllVerifier()
app.state.ingestion_processor = UnavailableProcessor()
app.state.graph_reader = None
app.state.trace_processor = UnavailableTraceProcessor()
app.state.trace_sessions = None
app.state.registration = None
app.state.topology_service = None
app.state.runtime_id = str(uuid4())
bearer = HTTPBearer(auto_error=False)


@app.on_event("startup")
def configure_test_services():
    """Configure local testing or the built-in NAuth issuer, failing closed."""
    app.state.runtime_id = str(uuid4())
    dsn = os.environ.get("NAVIS_DATABASE_URL")
    token = os.environ.get("NAVIS_LOCAL_TOKEN")
    mode = os.environ.get("NAVIS_AUTH_MODE", "local")
    if mode not in {"local", "nauth"}:
        raise RuntimeError("NAVIS_AUTH_MODE must be local or nauth")
    registered = mode == "nauth"
    if registered and (not dsn or token):
        raise RuntimeError("NAuth authentication requires a database and forbids NAVIS_LOCAL_TOKEN")
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
        from .topology import TopologyService
        app.state.topology_service = TopologyService(factory)
        if registered:
            from .registration import Registration
            service = Registration(factory)
            with factory() as conn, conn.cursor() as cur:
                cur.execute("SELECT id FROM navis.instance_identity WHERE singleton")
                identity = cur.fetchone()
                if identity is None:
                    raise RuntimeError("Run local registration init before starting API pods")
            app.state.instance_id = str(identity[0])
            app.state.registration = service
            app.state.token_verifier = service
    if token:
        from navis_common.local_auth import LocalTokenVerifier
        scopes = frozenset(os.environ.get("NAVIS_LOCAL_SCOPES", "").split())
        app.state.token_verifier = LocalTokenVerifier(token, Principal(
            subject=os.environ.get("NAVIS_LOCAL_SUBJECT", "local-test"),
            issuer=os.environ.get("NAVIS_LOCAL_ISSUER", "navis-local"), scopes=scopes))


app.post("/nauth/token", summary="Issue a client credentials access token",
         description="Authenticate with HTTP Basic client_id:client_secret. Requires HTTPS and locally provisioned clients.",
         openapi_extra={"requestBody": {"required": True, "content": {
             "application/x-www-form-urlencoded": {"schema": {"type": "object",
                 "required": ["grant_type"], "properties": {
                     "grant_type": {"type": "string", "enum": ["client_credentials"]},
                     "scope": {"type": "string", "description": "Space-separated subset of approved scopes"}}}}}}})(issue_token)


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
def submit_ingestion(submission: Ingestion, request: Request, background_tasks: BackgroundTasks,
                     principal: Principal = Depends(require_scope("inventory:write"))):
    try:
        receipt = request.app.state.ingestion_processor.submit(submission, principal)
        if request.app.state.topology_service is not None:
            background_tasks.add_task(request.app.state.topology_service.after_ingestion, principal, submission.source.namespace)
        return receipt
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
        if request.app.state.topology_service is not None:
            try:
                topology = request.app.state.topology_service.read(principal, parsed_id)
                identities = request.app.state.graph_reader(parsed_id, principal)
                by_id = {node["id"]: node for node in identities["nodes"]}
                return {**identities, **topology, "nodes": [
                    {**by_id.get(node["id"], {}), **node} for node in topology["nodes"]]}
            except LookupError:
                pass
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
        if submission.graph_build_id is None:
            service = request.app.state.topology_service
            if service is None:
                raise HTTPException(status_code=503, detail="Topology preparation is not configured")
            from uuid import UUID
            prepared = service.refresh(principal, submission.namespace)
            submission = submission.model_copy(update={"graph_build_id": UUID(prepared["graph_build_id"])})
        elif request.app.state.topology_service is not None:
            # Enforce ownership for named topology builds as well as trace source scope.
            try:
                request.app.state.topology_service.read(principal, submission.graph_build_id, permission="analysis:run")
            except LookupError:
                pass  # Legacy operator-created builds retain their existing checks.
        result = request.app.state.trace_processor.trace(submission, flows, principal)
        if request.app.state.trace_sessions is None:
            raise HTTPException(status_code=503, detail="Trace session storage is not configured")
        session_id = request.app.state.trace_sessions.save(principal, submission.caller_session_id, submission.graph_build_id, submission.model_dump(mode="json"), result)
        return {**result, "graph_build_id": str(submission.graph_build_id), "code": "TRACE_RESULT_READY", "caller_session_id": submission.caller_session_id, "trace_session_id": str(session_id)}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Dataset access denied")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except NotImplementedError:
        raise HTTPException(status_code=503, detail="Trace analysis is not configured")


def topology_service(request):
    if request.app.state.topology_service is None:
        raise HTTPException(status_code=503, detail="Topology storage is not configured")
    return request.app.state.topology_service


@app.post("/v1/topologies", status_code=201)
def prepare_topology(submission: TopologyRequest, request: Request,
                     principal: Principal = Depends(require_scope("analysis:run"))):
    try:
        return topology_service(request).refresh(principal, submission.namespace, name=submission.name, ips=submission.ips)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Namespace access denied")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/v1/graph-builds")
def list_builds(request: Request, namespace: str | None = None, limit: int = Query(default=50, ge=1, le=200),
                principal: Principal = Depends(require_scope("graph:read"))):
    try:
        return topology_service(request).list_builds(principal, namespace, limit)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Consumer access denied")


@app.get("/v1/ingestions/{ingestion_id}")
def ingestion_status(ingestion_id: str, request: Request,
                     principal: Principal = Depends(require_scope("inventory:write"))):
    from uuid import UUID
    try:
        parsed = UUID(ingestion_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid ingestion ID")
    try:
        return topology_service(request).ingestion_status(principal, parsed)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Consumer access denied")
    except LookupError:
        raise HTTPException(status_code=404, detail="Ingestion not found or inaccessible")


@app.get("/v1/topologies/{build_id}")
def read_topology(build_id: str, request: Request,
                  principal: Principal = Depends(require_scope("graph:read"))):
    from uuid import UUID
    try:
        parsed = UUID(build_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid graph build ID")
    try:
        return topology_service(request).read(principal, parsed)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Topology access denied")
    except LookupError:
        raise HTTPException(status_code=404, detail="Topology not found")


@app.get("/v1/trace-sessions/{caller_session_id}/graph")
def session_graph(caller_session_id: str, request: Request,
                  principal: Principal = Depends(require_scope("analysis:read"))):
    if request.app.state.trace_sessions is None:
        raise HTTPException(status_code=503, detail="Session storage is not configured")
    try:
        session = request.app.state.trace_sessions.get(principal, caller_session_id)
        # Session ownership and current analysis access are both checked.
        graph = topology_service(request).read(principal, session["graph_build_id"], permission="analysis:run")
        from .topology import application_view
        saved_request = TraceRequest.model_validate(session["request"])
        ips = sorted({ip for flow in saved_request.flows() for ip in (flow.source, flow.destination)})
        full_graph = graph
        graph = application_view(graph, ips)
        traced = {h["device_id"] for result in session["result"].get("results", [])
                  for h in result.get("hops", []) if h.get("device_id")}
        selected = traced | {node["id"] for node in graph["nodes"]}
        graph["nodes"] = [node for node in full_graph["nodes"] if node["id"] in selected]
        graph["connections"] = [edge for edge in full_graph["connections"]
                                if edge["source"] in selected and edge["target"] in selected]
        return {**session, "graph": graph}
    except PermissionError:
        raise HTTPException(status_code=403, detail="Session or source access denied")
    except LookupError:
        raise HTTPException(status_code=404, detail="Session graph not found or expired")


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
