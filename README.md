#  Aegis Proxy: Secure Financial Firewall for Autonomous AI Agents

**Aegis Proxy** is a high-performance, asynchronous, deterministic security gateway and financial firewall designed specifically for Autonomous AI Agents. Instead of giving AI agents unrestricted API keys to payment and SaaS providers (e.g., Stripe, Twilio, OpenAI), developers issue scoped **Aegis Tokens**. Aegis Proxy intercepts all requests, enforces YAML security policies, performs SQLite budget checks, evaluates semantic anomalies using local ChromaDB vector search, and safely forwards or blocks transactions.

---

##  Architecture & Security Model

```
                                      AEGIS PROXY
  +--------------+        +-------------------------------------------------+
  |              |  HTTP  |  1. Auth & Token Validation (Aegis-Token)       |
  |   AI Agent   |------->|  2. Load & Cache Agent Policy (YAML)             |
  | (Scoped Key) |        |  3. Deterministic Domain & Method Allowlist     |
  +--------------+        |  4. SQLite Ledger Budget Tracking ($ Daily)     |
                          |  5. ChromaDB Vector Semantic Anomaly Check        |
                          +-------------------------------------------------+
                                       |                      |
                            (If Blocked)              (If Passed)
                                       v                      v
                          +------------------+   +--------------------------+
                          | Return HTTP 403  |   | Inject Upstream Secret   |
                          | Explainable JSON |   | & Forward via HTTPX      |
                          +------------------+   +--------------------------+
                                                              |
                                                              v
                                                    +--------------------+
                                                    | External Vendor    |
                                                    | (Stripe / Twilio)  |
                                                    +--------------------+
```

---

##  Key Features

1. **Zero-Trust Input Validation**: Built with Pydantic V2 enforcing strict type-checking, regex URL validation, and forbidding unparsed extra kwargs.
2. **Absolute Secret Hygiene**: Every log output passes through automated header and payload redaction regex masking (`[REDACTED]`). Real vendor API keys are injected exclusively from `.env` via `pydantic-settings`.
3. **Asynchronous Purity**: Built on FastAPI, `httpx.AsyncClient`, `aiofiles`, and `aiosqlite` with zero blocking event-loop calls.
4. **Deterministic Budget Rules**: Tracks historical spending in SQLite ledger for daily/monthly budget caps and single transaction cost limits.
5. **Semantic Anomaly Detection**: Embeds request intent and payload using a local persistent **ChromaDB** vector store to detect prompt injections, unauthorized drain attempts, and policy bypass attacks.
6. **Explainable Error Codes**: Returns structured JSON error codes (`BUDGET_EXCEEDED`, `DOMAIN_NOT_ALLOWED`, `SEMANTIC_ANOMALY_DETECTED`) allowing AI agents to understand and adapt.

---

##  Repository Structure

```
paysafe/
├── .env.example             # Template for master keys and vendor secrets
├── config.py                # Pydantic Settings V2 & Async YAML policy loader
├── models.py                # Strict Pydantic V2 schemas for validation & audit
├── security.py              # Aegis Token parsing, secret injection & header/body redaction
├── logger.py                # Structlog configuration for structured JSON logging
├── ledger.py                # Async SQLite SQLAlchemy model & spending query helpers
├── vector_store.py          # ChromaDB initialization & semantic anomaly detector
├── main.py                  # FastAPI proxy application router & exception handlers
├── policies/
│   └── agent_001.yaml       # Example agent YAML policy configuration
├── requirements.txt         # Production dependencies
├── run_tests.py             # Test suite execution runner
└── test_aegis.py            # Automated integration & unit tests
```

---

## Getting Started

### 1. Installation

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Environment Configuration

Copy `.env.example` to `.env` and set your master key and vendor API keys:

```bash
cp .env.example .env
```

### 3. Agent Policy Configuration (`policies/agent_001.yaml`)

```yaml
agent_id: agent_001
name: Financial Execution & Billing Agent
daily_budget: 50.0
monthly_budget: 500.0
max_single_transaction_cost: 25.0
allowed_domains:
  - api.stripe.com
  - api.twilio.com
  - httpbin.org
allowed_methods:
  - GET
  - POST
api_key_mappings:
  api.stripe.com: STRIPE_API_KEY
  api.twilio.com: TWILIO_API_KEY
  httpbin.org: OPENAI_API_KEY
rate_limit_per_minute: 60
```

### 4. Running the Aegis Proxy Server

```bash
uvicorn main:app --reload --port 8000
```

---

## 🧪 Testing & Verification

Run the automated integration test suite:

```bash
python run_tests.py
```

---

##  API Reference

### Intercept & Forward Request
`POST /v1/proxy/forward`
- **Headers**: `Aegis-Token: aegis_token_agent_001_secret123`
- **Body**:
  ```json
  {
    "target_url": "https://api.stripe.com/v1/charges",
    "method": "POST",
    "payload": {"amount": 2000, "currency": "usd"},
    "intent_description": "Charge user for tier 1 subscription",
    "estimated_cost_usd": 0.05
  }
  ```

### Audit Ledger History
`GET /v1/audit/ledger/{agent_id}`

### Budget Breakdown Status
`GET /v1/audit/budget/{agent_id}`

### Seed Anomaly Pattern
`POST /v1/anomalies/seed?pattern=...&label=...`
