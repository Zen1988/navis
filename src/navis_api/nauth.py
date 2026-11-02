"""NAuth token endpoint: confidential clients authenticate with HTTP Basic."""
import base64
import binascii
import re
from urllib.parse import parse_qsl, unquote_plus
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from .registration import NAuthError

NO_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def error(code, status=400):
    headers = dict(NO_CACHE)
    if status == 401:
        headers["WWW-Authenticate"] = 'Basic realm="navis-token"'
    return JSONResponse({"error": code}, status_code=status, headers=headers)


async def issue_token(request: Request):
    if request.app.state.registration is None:
        return error("temporarily_unavailable", 503)
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
        return error("invalid_request")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 4096:
            return error("invalid_request")
    try:
        pairs = parse_qsl(body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=10)
    except (UnicodeError, ValueError):
        return error("invalid_request")
    form = dict(pairs)
    if len(pairs) != len(form) or "client_secret" in form or "client_id" in form:
        return error("invalid_request")
    authorization = request.headers.get("authorization", "")
    try:
        scheme, encoded = authorization.split(" ", 1)
        if scheme.lower() != "basic" or len(encoded) > 2048:
            raise ValueError()
        decoded = base64.b64decode(encoded, validate=True).decode("ascii")
        client_id, secret = decoded.split(":", 1)
        client_id, secret = unquote_plus(client_id), unquote_plus(secret)
        if not client_id or not secret:
            raise ValueError()
    except (ValueError, UnicodeError, binascii.Error):
        return error("invalid_client", 401)
    if "grant_type" not in form:
        return error("invalid_request")
    if form["grant_type"] != "client_credentials":
        return error("unsupported_grant_type")
    if "scope" in form and not re.fullmatch(r'[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*', form["scope"]):
        return error("invalid_scope")
    try:
        result = await run_in_threadpool(request.app.state.registration.token, client_id, secret, form.get("scope"))
    except NAuthError as exc:
        return error(exc.error, 401 if exc.error == "invalid_client" else 400)
    except Exception:
        # Never include database diagnostics or credentials in a NAuth error.
        return error("temporarily_unavailable", 503)
    return JSONResponse(result, headers=NO_CACHE)
