"""
Aegis Proxy - Security & Secret Hygiene Module.

Handles Aegis token verification, header and body redaction to prevent secret leaks,
and downstream secret injection from environment variables via pydantic-settings.
"""

import os
import re
from typing import Any, Dict, Optional, Tuple

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "aegis-token",
    "x-api-key",
    "api-key",
    "bearer",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "secret",
}

SENSITIVE_BODY_KEYS = {
    "card_number",
    "card_cvv",
    "cvv",
    "password",
    "secret",
    "api_key",
    "token",
    "private_key",
    "ssn",
    "account_number",
}


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Returns a copy of headers with all sensitive values masked with [REDACTED].

    Args:
        headers: Dictionary of HTTP request or response headers.

    Returns:
        Redacted dictionary safe for logging or storage.
    """
    redacted = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_KEYS:
            redacted[key] = "[REDACTED]"
        else:
            # Also apply regex mask if bearer token string pattern is matched in value
            if re.search(r"(bearer|sk_test|sk_live|key-[a-z0-9]+)", value, re.IGNORECASE):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
    return redacted


def redact_body(data: Any) -> Any:
    """
    Recursively redacts sensitive payload fields in JSON-compatible dictionaries or lists.

    Args:
        data: Dict, List, or primitive body data.

    Returns:
        Safe data structure with sensitive values replaced by [REDACTED].
    """
    if isinstance(data, dict):
        cleaned_dict = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_BODY_KEYS:
                cleaned_dict[k] = "[REDACTED]"
            else:
                cleaned_dict[k] = redact_body(v)
        return cleaned_dict
    elif isinstance(data, list):
        return [redact_body(item) for item in data]
    else:
        return data


def verify_aegis_token(token: Optional[str]) -> Tuple[bool, str, Optional[str]]:
    """
    Validates an Aegis proxy token provided in HTTP headers.

    Expected Token Format: "Bearer aegis_token_<agent_id>_<hash_or_secret>"
    or direct "aegis_token_<agent_id>_<hash_or_secret>"

    Args:
        token: Raw header string (e.g. from Aegis-Token or Authorization).

    Returns:
        Tuple of (is_valid: bool, agent_id: str, error_message: Optional[str]).
    """
    if not token or not token.strip():
        return False, "", "Missing Aegis-Token header"

    raw_token = token.strip()
    if raw_token.lower().startswith("bearer "):
        raw_token = raw_token[7:].strip()

    # Pattern match: aegis_token_<agent_id>_<secret> or aegis-<agent_id>-token
    match = re.match(r"^aegis_token_([a-zA-Z0-9_-]{3,64})_([a-zA-Z0-9_-]+)$", raw_token)
    if match:
        agent_id = match.group(1)
        secret = match.group(2)
        if len(secret) < 4:
            return False, agent_id, "Aegis token secret signature is invalid or too short"
        return True, agent_id, None

    match_alt = re.match(r"^aegis-([a-zA-Z0-9_-]{3,64})-token$", raw_token)
    if match_alt:
        agent_id = match_alt.group(1)
        return True, agent_id, None

    return False, "", "Invalid Aegis token format. Expected: aegis_token_<agent_id>_<secret>"


def inject_upstream_credentials(
    incoming_headers: Dict[str, str],
    mapping_env_var: Optional[str],
) -> Dict[str, str]:
    """
    Prepares headers for downstream forwarding by:
    1. Stripping Aegis authentication headers.
    2. Injecting the real API key loaded from environment variables if a mapping exists.

    Args:
        incoming_headers: Headers sent by the AI Agent.
        mapping_env_var: Name of the environment variable containing the real API key (e.g., 'STRIPE_API_KEY').

    Returns:
        Forwarding-ready headers dictionary.
    """
    forward_headers = {}
    for k, v in incoming_headers.items():
        k_lower = k.lower()
        if k_lower in ("aegis-token", "x-aegis-token", "host", "content-length"):
            continue
        forward_headers[k] = v

    if mapping_env_var:
        real_api_key = os.getenv(mapping_env_var)
        if real_api_key:
            # Inject Authorization header with the real secret
            forward_headers["Authorization"] = f"Bearer {real_api_key}"
            forward_headers["X-Api-Key"] = real_api_key

    return forward_headers
