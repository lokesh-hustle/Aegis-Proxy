"""
Aegis Proxy - Main FastAPI Application.

Brings together input validation, policy evaluation, SQLite budget tracking,
ChromaDB semantic anomaly detection, and async httpx downstream request forwarding.
"""

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from config import load_agent_policy, settings
from ledger import (
    get_agent_history,
    get_daily_spending,
    get_db_session,
    get_monthly_spending,
    init_db,
    record_transaction,
)
from logger import logger
from models import AegisErrorResponse, ProxyRequest, TransactionRecordSchema
from security import (
    inject_upstream_credentials,
    redact_body,
    redact_headers,
    verify_aegis_token,
)
from vector_store import add_malicious_vector, check_semantic_anomaly, init_vector_store

# Lifespan application event handler for startup/shutdown
async def lifespan(app: FastAPI):
    """Handles startup DB and Vector Store initialization."""
    logger.info("Initializing Aegis Proxy security services...")
    await init_db()
    init_vector_store()
    logger.info("Aegis Proxy operational.")
    yield
    logger.info("Shutting down Aegis Proxy.")


app = FastAPI(
    title="Aegis Proxy",
    description="Deterministic, Hardened Financial Firewall for Autonomous AI Agents",
    version="1.0.0",
    lifespan=lifespan,
)


FALLBACK_HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Aegis Proxy - API Running</title>
  <style>
    body { font-family: system-ui; background: #0b0f19; color: #f8fafc; padding: 3rem; text-align: center; }
    .card { background: #161e2e; border: 1px solid #334155; padding: 2rem; border-radius: 12px; max-width: 600px; margin: auto; }
    h1 { color: #38bdf8; }
    code { color: #34d399; background: #090d16; padding: 0.2rem 0.5rem; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Aegis Proxy is ONLINE</h1>
    <p style="margin: 1rem 0; color: #94a3b8;">API Gateway is operational. (dashboard.html not found, serving fallback status page).</p>
    <p>Send <code>POST</code> requests to <code>/v1/proxy/forward</code> with a valid <code>Aegis-Token</code>.</p>
  </div>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def root_dashboard():
    """
    Serves the interactive single-file UI dashboard (dashboard.html) for hackathon judges and landing users.
    Includes try/except fallback if dashboard.html is missing.
    """
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    try:
        with open(dashboard_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content)
    except FileNotFoundError:
        logger.warning("dashboard.html file not found, serving fallback dashboard", path=dashboard_path)
        return HTMLResponse(content=FALLBACK_HTML_DASHBOARD)


# Centralized Exception Handlers (Prevent stack trace leakage)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    trace_id = str(uuid.uuid4())
    logger.warning("Request schema validation failed", trace_id=trace_id, errors=exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=AegisErrorResponse(
            status="ERROR",
            error_code="INVALID_INPUT_SCHEMA",
            message="Request payload failed Pydantic V2 validation schema.",
            details={"validation_errors": exc.errors()},
            trace_id=trace_id,
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    trace_id = str(uuid.uuid4())
    logger.error("Unhandled internal server exception", trace_id=trace_id, error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=AegisErrorResponse(
            status="ERROR",
            error_code="INTERNAL_SERVER_ERROR",
            message="An internal server error occurred while processing the request.",
            details={},
            trace_id=trace_id,
        ).model_dump(),
    )


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check endpoint."""
    return {"status": "ok", "service": "Aegis Proxy", "timestamp": time.time()}


@app.post(
    "/v1/proxy/forward",
    tags=["Proxy Intercept"],
    response_model=None,
    summary="Intercept, evaluate, and forward AI agent HTTP request",
)
async def proxy_forward(
    request_data: ProxyRequest,
    aegis_token: Optional[str] = Header(None, alias="Aegis-Token"),
    x_aegis_token: Optional[str] = Header(None, alias="X-Aegis-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    session: AsyncSession = Depends(get_db_session),
):
    """
    Core Aegis Intercept Workflow:
    1. Authenticate Aegis-Token.
    2. Load agent YAML policy.
    3. Check Allowlisted domain and HTTP method.
    4. Check single transaction cost & daily/monthly budget limits via SQLite Ledger.
    5. Check semantic payload/intent anomaly via ChromaDB.
    6. Forward downstream with injected API keys or return structured 403 error.
    """
    trace_id = str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(trace_id=trace_id)

    # 1. Token Verification
    raw_token = aegis_token or x_aegis_token or authorization
    is_valid, agent_id, auth_error = verify_aegis_token(raw_token)

    if not is_valid:
        logger.warning("Authentication failed", error=auth_error)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="AUTHENTICATION_FAILED",
                message=auth_error or "Invalid or missing Aegis authorization token.",
                details={},
                trace_id=trace_id,
            ).model_dump(),
        )

    structlog.contextvars.bind_contextvars(agent_id=agent_id)

    # 2. Load Agent Policy
    try:
        policy = await load_agent_policy(agent_id)
    except FileNotFoundError:
        logger.warning("Agent policy file not found", agent_id=agent_id)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=str(request_data.target_url),
            domain=urlparse(str(request_data.target_url)).netloc,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason="POLICY_NOT_FOUND",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="POLICY_NOT_FOUND",
                message=f"No YAML security policy configured for agent '{agent_id}'.",
                details={"agent_id": agent_id},
                trace_id=trace_id,
            ).model_dump(),
        )

    target_url_str = str(request_data.target_url)
    parsed_url = urlparse(target_url_str)
    domain = parsed_url.netloc.lower()

    # 3. Domain Allowlist Check
    if domain not in policy.allowed_domains:
        logger.warning("Domain not allowlisted", domain=domain, allowed=policy.allowed_domains)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason=f"DOMAIN_NOT_ALLOWED: {domain}",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="DOMAIN_NOT_ALLOWED",
                message=f"Target domain '{domain}' is not in the allowed domain list.",
                details={"domain": domain, "allowed_domains": policy.allowed_domains},
                trace_id=trace_id,
            ).model_dump(),
        )

    # 4. Method Check
    if request_data.method not in policy.allowed_methods:
        logger.warning("HTTP Method not allowed", method=request_data.method, allowed=policy.allowed_methods)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason=f"METHOD_NOT_ALLOWED: {request_data.method}",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="METHOD_NOT_ALLOWED",
                message=f"HTTP method '{request_data.method}' is not permitted for domain '{domain}'.",
                details={"method": request_data.method, "allowed_methods": policy.allowed_methods},
                trace_id=trace_id,
            ).model_dump(),
        )

    # 5. Single Transaction Cost Cap Check
    req_cost = request_data.estimated_cost_usd
    if req_cost > policy.max_single_transaction_cost:
        logger.warning("Single transaction limit exceeded", cost=req_cost, max_allowed=policy.max_single_transaction_cost)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason=f"SINGLE_TRANSACTION_LIMIT_EXCEEDED: ${req_cost} > ${policy.max_single_transaction_cost}",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="SINGLE_TRANSACTION_LIMIT_EXCEEDED",
                message=f"Request cost of ${req_cost} exceeds single transaction cap of ${policy.max_single_transaction_cost}.",
                details={"requested_cost": req_cost, "max_allowed": policy.max_single_transaction_cost},
                trace_id=trace_id,
            ).model_dump(),
        )

    # 6. Budget Evaluation (Daily & Monthly Aggregation)
    daily_spent = await get_daily_spending(session, agent_id)
    monthly_spent = await get_monthly_spending(session, agent_id)

    if (daily_spent + req_cost) > policy.daily_budget:
        logger.warning("Daily budget limit exceeded", spent=daily_spent, req_cost=req_cost, budget=policy.daily_budget)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason=f"DAILY_BUDGET_EXCEEDED: ${daily_spent + req_cost:.2f} / ${policy.daily_budget:.2f}",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="DAILY_BUDGET_EXCEEDED",
                message=f"Request of ${req_cost} would exceed daily budget. Spent: ${daily_spent:.2f}, Limit: ${policy.daily_budget:.2f}.",
                details={"daily_spent": daily_spent, "requested_cost": req_cost, "daily_budget": policy.daily_budget},
                trace_id=trace_id,
            ).model_dump(),
        )

    if (monthly_spent + req_cost) > policy.monthly_budget:
        logger.warning("Monthly budget limit exceeded", spent=monthly_spent, req_cost=req_cost, budget=policy.monthly_budget)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason=f"MONTHLY_BUDGET_EXCEEDED: ${monthly_spent + req_cost:.2f} / ${policy.monthly_budget:.2f}",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="MONTHLY_BUDGET_EXCEEDED",
                message=f"Request of ${req_cost} would exceed monthly budget. Spent: ${monthly_spent:.2f}, Limit: ${policy.monthly_budget:.2f}.",
                details={"monthly_spent": monthly_spent, "requested_cost": req_cost, "monthly_budget": policy.monthly_budget},
                trace_id=trace_id,
            ).model_dump(),
        )

    # 7. Semantic Anomaly Check (Vector DB)
    payload_str = json.dumps(request_data.payload) if request_data.payload else ""
    check_text = f"{request_data.intent_description or ''} {payload_str}".strip()

    is_anomaly, similarity, threat_label = check_semantic_anomaly(
        text_content=check_text,
        threshold=settings.default_anomaly_threshold,
    )

    if is_anomaly:
        logger.warning("Semantic anomaly blocked transaction", threat=threat_label, similarity=similarity)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="BLOCKED",
            block_reason=f"SEMANTIC_ANOMALY: {threat_label} (score: {similarity})",
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AegisErrorResponse(
                status="BLOCKED",
                error_code="SEMANTIC_ANOMALY_DETECTED",
                message=f"Request payload/intent flagged as potential threat: '{threat_label}'.",
                details={"similarity_score": similarity, "threat_label": threat_label},
                trace_id=trace_id,
            ).model_dump(),
        )

    # 8. All Deterministic & Semantic Checks Passed -> Execute Downstream Request
    mapping_env_var = policy.api_key_mappings.get(domain)
    forward_headers = inject_upstream_credentials(request_data.headers, mapping_env_var)

    redacted_req_headers = redact_headers(forward_headers)
    redacted_payload = redact_body(request_data.payload)

    logger.info(
        "Forwarding request to upstream API",
        target_url=target_url_str,
        method=request_data.method,
        headers=redacted_req_headers,
        payload=redacted_payload,
    )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.request(
                method=request_data.method,
                url=target_url_str,
                headers=forward_headers,
                json=request_data.payload,
            )

        # Record successful transaction in SQLite Ledger
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=req_cost,
            status="SUCCESS",
        )

        # Log sanitized response metadata
        safe_resp_headers = redact_headers(dict(resp.headers))
        logger.info(
            "Downstream API request completed successfully",
            status_code=resp.status_code,
            headers=safe_resp_headers,
        )

        try:
            resp_content = resp.json()
        except Exception:
            resp_content = {"raw_content": resp.text}

        return JSONResponse(
            status_code=resp.status_code,
            content={
                "aegis_status": "FORWARDED",
                "trace_id": trace_id,
                "downstream_status": resp.status_code,
                "response": resp_content,
            },
        )

    except httpx.TimeoutException:
        logger.error("Downstream API request timed out", target_url=target_url_str)
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="FAILED",
            block_reason="DOWNSTREAM_TIMEOUT",
        )
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content=AegisErrorResponse(
                status="ERROR",
                error_code="DOWNSTREAM_TIMEOUT",
                message=f"Request to upstream server '{domain}' timed out.",
                details={"domain": domain},
                trace_id=trace_id,
            ).model_dump(),
        )
    except httpx.RequestError as exc:
        logger.error("Downstream connection error", error=str(exc))
        await record_transaction(
            session=session,
            agent_id=agent_id,
            trace_id=trace_id,
            target_url=target_url_str,
            domain=domain,
            method=request_data.method,
            cost_usd=0.0,
            status="FAILED",
            block_reason=f"DOWNSTREAM_ERROR: {str(exc)}",
        )
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content=AegisErrorResponse(
                status="ERROR",
                error_code="DOWNSTREAM_CONNECTION_ERROR",
                message=f"Failed to connect to upstream server '{domain}'.",
                details={"error": str(exc)},
                trace_id=trace_id,
            ).model_dump(),
        )


@app.get(
    "/v1/audit/ledger/{agent_id}",
    tags=["Audit & Monitoring"],
    response_model=List[TransactionRecordSchema],
    summary="Fetch transaction ledger audit history for an agent",
)
async def get_ledger_history(
    agent_id: str,
    limit: int = 50,
    session: AsyncSession = Depends(get_db_session),
):
    """Returns past ledger transactions for the specified agent."""
    history = await get_agent_history(session, agent_id, limit=limit)
    records = []
    for item in history:
        records.append(
            TransactionRecordSchema(
                id=item.id,
                agent_id=item.agent_id,
                trace_id=item.trace_id,
                timestamp=item.timestamp.isoformat(),
                target_url=item.target_url,
                domain=item.domain,
                method=item.method,
                cost_usd=item.cost_usd,
                status=item.status,
                block_reason=item.block_reason,
            )
        )
    return records


@app.get(
    "/v1/audit/budget/{agent_id}",
    tags=["Audit & Monitoring"],
    summary="Get current budget spending breakdown for an agent",
)
async def get_budget_status(
    agent_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Calculates daily and monthly spent vs configured limits."""
    try:
        policy = await load_agent_policy(agent_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Policy for agent '{agent_id}' not found.")

    daily_spent = await get_daily_spending(session, agent_id)
    monthly_spent = await get_monthly_spending(session, agent_id)

    return {
        "agent_id": agent_id,
        "daily_spent_usd": round(daily_spent, 2),
        "daily_budget_usd": policy.daily_budget,
        "daily_remaining_usd": round(max(0.0, policy.daily_budget - daily_spent), 2),
        "monthly_spent_usd": round(monthly_spent, 2),
        "monthly_budget_usd": policy.monthly_budget,
        "monthly_remaining_usd": round(max(0.0, policy.monthly_budget - monthly_spent), 2),
    }


@app.post(
    "/v1/anomalies/seed",
    tags=["Security Administration"],
    summary="Seed new malicious vector into ChromaDB",
)
async def seed_anomaly(
    pattern: str,
    label: str = "Custom Threat",
):
    """Adds a new malicious intent pattern vector to the ChromaDB database."""
    doc_id = add_malicious_vector(text=pattern, label=label)
    return {"status": "SUCCESS", "vector_id": doc_id, "label": label, "pattern": pattern}
