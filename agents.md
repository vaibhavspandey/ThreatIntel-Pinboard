# TIPinBoard AI Agent Guidelines

This file serves as the ultimate source of truth and system prompt for any AI agents working on this codebase. It must be strictly followed to prevent agents from making assumptions that break the architecture, custom logic, or threat intel mechanics of the TIPinBoard project.

## 1. Project Overview & Tech Stack
* **Name:** TIPinBoard (Threat Intelligence Pinboard)
* **Purpose:** An automated workbench that transitions static IOCs into active, longitudinally tracked intelligence traps.
* **Tech Stack:**
  * **Backend:** FastAPI, SQLAlchemy, PostgreSQL (Fallback to SQLite)
  * **Frontend:** Streamlit
  * **Worker:** Custom Python scheduled script using `apscheduler`
  * **Infrastructure:** Docker Compose (Use `./openpinboard` script or `docker compose` to start services)

## 2. Architectural Rules & Constraints
* **Docker Networking (CRITICAL):** Agents must NEVER use `localhost` for container-to-container communication. The service names are `frontend`, `backend`, `db`, and `monitor`. The Frontend must route to the Backend using `http://backend:8000` (configured via `API_BASE_URL`).
* **Database Constraints:** The primary database is PostgreSQL via the `db` container. Agents must use SQLAlchemy ORM for all database interactions. Be aware that if Alembic migrations fail, the system silently falls back to `Base.metadata.create_all()`.
* **Single User Context:** The system currently has no AuthN/AuthZ. It is hardcoded to a default user named "analyst".

## 3. The Delta Engine (`monitor/delta_engine.py`)
Agents must understand the current "Logic State" before modifying:
* **Data Storage:** We currently use a "Raw Dump" strategy. External API JSON responses are stored entirely in `full_report_json` without normalization. Do NOT attempt to normalize data schema unless explicitly instructed.
* **Alert Sensitivity (Absolute):** The engine alerts on absolute changes. If `new_malicious > old_malicious`, an alert fires. It also alerts on new distinct items in sets (e.g., new DNS resolutions) or string changes. Do not alter this sensitivity logic unless instructed to build Phase 2 Smart Thresholds.
* **Missing Data:** If an API connector returns `None`, the engine safely ignores the comparison.

## 4. Threat Intel API Connectors (`monitor/connectors.py`)
Current active integrations and their required `.env` keys:
* **VirusTotal:** `VIRUSTOTAL_API_KEY` (Uses V3 API)
* **MalwareBazaar:** `MALWAREBAZAAR_API_KEY`
* **urlscan.io:** `URLSCAN_API_KEY` (Uses search endpoint)
* **Neiki TIP:** `NEIKI_API_KEY` (Uses V2 API `tip.neiki.dev/api`. Auth uses `Authorization: <apikey>` with NO Bearer prefix).
* **RSS Feeds:** No key required.

* **Gotcha - Rate Limiting:** There is a 1.0-second sleep enforced between calls to the *same* API to prevent rate-limiting bans.

## 5. Input Validation & Normalization Gotchas
* **Strict Pydantic Validation:** The backend uses strict Pydantic models. Malformed IOCs will throw 422 errors.
* **URL Normalization:** If a user submits a full URL under the `domain` type (e.g., `https://example.com/path`), the backend silently strips the path and scheme, storing only the network location (`example.com`).
* **Known Blind Spot:** `ioc_type = 'url'` is currently a known blind spot and is ignored by connectors.

## 6. MANDATORY RULE: Adding New APIs
Whenever an AI agent is tasked with adding a new API integration, it MUST first update this `agents.md` file under Section 4 with the following details:
1. The name of the API.
2. The specific endpoints used and the exact JSON payload/keys extracted.
3. How authentication is handled (e.g., Bearer, custom header).
4. What the required `.env` entry looks like.
5. Any constraints (e.g., rate limits, specific exception handling required).

All new connectors MUST include `try/except` blocks and return `None` on failure to prevent crashing the monitor loop (which runs every 1 hour).

## 7. Verification Commands
To test your changes, use the following commands:
* To build and start the services: `docker compose up --build -d` (or use `./openpinboard` if applicable)
* To view logs and troubleshoot issues: `docker compose logs -f` (you can append a service name like `docker compose logs -f backend` to see specific logs)
