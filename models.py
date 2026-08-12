"""
Aegis Proxy - Pydantic Schemas & Data Models.

Defines strict Pydantic V2 models for zero-trust validation of agent policies,
incoming proxy requests, error responses, and audit ledger entries.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class AgentPolicy(BaseModel):
    """
    Pydantic V2 model for Agent Policy YAML validation.
    Strictly forbids extra fields to prevent injection or invalid rules.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    agent_id: str = Field(
        ...,
        pattern=r"^[a-zA-Z0-9_-]{3,64}$",
        description="Unique identifier for the agent (alphanumeric, hyphens, underscores)",
    )
    name: str = Field(..., min_length=2, max_length=128, description="Human readable agent name")
    daily_budget: float = Field(..., gt=0.0, description="Maximum total USD spending allowed per day")
    monthly_budget: float = Field(..., gt=0.0, description="Maximum total USD spending allowed per month")
    max_single_transaction_cost: float = Field(
        default=50.0,
        gt=0.0,
        description="Maximum cost allowed for a single API call",
    )
    allowed_domains: List[str] = Field(
        ...,
        min_length=1,
        description="List of domain names allowed for forwarding (e.g. api.stripe.com)",
    )
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST"],
        description="List of allowed HTTP methods",
    )
    api_key_mappings: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of domain names to secret environment variable names containing the real API key",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        gt=0,
        le=1000,
        description="Maximum allowed requests per minute",
    )

    @field_validator("allowed_domains")
    @classmethod
    def normalize_domains(cls, domains: List[str]) -> List[str]:
        """Normalizes domains to lowercase without protocol prefixes."""
        cleaned = []
        for domain in domains:
            d = domain.strip().lower()
            if d.startswith("http://"):
                d = d[7:]
            elif d.startswith("https://"):
                d = d[8:]
            cleaned.append(d.split("/")[0])
        return cleaned

    @field_validator("allowed_methods")
    @classmethod
    def normalize_methods(cls, methods: List[str]) -> List[str]:
        """Normalizes HTTP methods to uppercase."""
        valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        cleaned = []
        for m in methods:
            upper_m = m.strip().upper()
            if upper_m not in valid_methods:
                raise ValueError(f"Invalid HTTP method: {m}")
            cleaned.append(upper_m)
        return cleaned


class ProxyRequest(BaseModel):
    """
    Incoming HTTP request wrapper from the AI Agent.
    Strictly forbids extra parameters.
    """

    model_config = ConfigDict(extra="forbid")

    target_url: HttpUrl = Field(..., description="Fully qualified destination URL (https://...)")
    method: str = Field(default="POST", description="HTTP Method (GET, POST, etc.)")
    headers: Dict[str, str] = Field(default_factory=dict, description="Headers to forward downstream")
    payload: Optional[Dict[str, Any]] = Field(default=None, description="JSON body payload to forward")
    intent_description: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Natural language summary of agent request intent for semantic anomaly evaluation",
    )
    estimated_cost_usd: float = Field(
        default=0.01,
        ge=0.0,
        le=1000.0,
        description="Estimated transaction cost in USD for budget pre-reservation",
    )

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        upper = v.strip().upper()
        if upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"Unsupported HTTP method: {v}")
        return upper


class AegisErrorResponse(BaseModel):
    """
    Structured, explainable JSON error response returned on transaction block or failure.
    """

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="BLOCKED", description="Status indicator: BLOCKED or ERROR")
    error_code: str = Field(..., description="Machine-readable error code (e.g., BUDGET_EXCEEDED)")
    message: str = Field(..., description="Clear human-readable explanation")
    details: Dict[str, Any] = Field(default_factory=dict, description="Context details (e.g. current budget spent)")
    trace_id: str = Field(..., description="Unique request tracing ID")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp",
    )


class TransactionRecordSchema(BaseModel):
    """
    Pydantic schema for audit reporting of recorded transactions.
    """

    model_config = ConfigDict(extra="forbid")

    id: int
    agent_id: str
    trace_id: str
    timestamp: str
    target_url: str
    domain: str
    method: str
    cost_usd: float
    status: str
    block_reason: Optional[str] = None
