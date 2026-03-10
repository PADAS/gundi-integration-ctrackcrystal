# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Gundi v2 integration connector that pulls vehicle tracking data from the Ctrack Crystal API, transforms it to Gundi schema, and sends observations to the Gundi platform. Runs as a FastAPI microservice with Redis for state/config caching and GCP Pub/Sub for event-driven triggers.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run a specific test file
pytest app/actions/tests/test_handlers.py

# Run a single test by name
pytest app/actions/tests/test_handlers.py::test_action_pull_observations_fetches_vehicle_trips_inline

# Compile requirements after changing .in files
pip-compile --output-file=requirements.txt requirements-base.in requirements-dev.in requirements.in

# Local dev with Docker (Redis + Pub/Sub emulator included)
cd local && docker compose up --build

# Run directly (requires Redis running)
uvicorn app.main:app --reload --port 8080
```

There is no linter configured in this project.

## Architecture

**Layered structure:**
- `app/routers/` — FastAPI endpoints (action execution, webhooks, config events)
- `app/services/` — Orchestration layer (action runner, state management, config caching, Gundi client, activity logging)
- `app/actions/` — Pluggable action handlers discovered dynamically by `action_` prefix
- `app/datasource/ctrackcrystal/` — HTTP client for the Ctrack Crystal API with retry/backoff logic
- `app/settings/` — Environment-based configuration

**Action system:** Actions are async functions prefixed with `action_` in `handlers.py`. Each has a Pydantic config model in `configurations.py`. The framework discovers them via `discover_actions()` in `core.py` and matches them to integration configurations from the Gundi portal.

**Key action flow (pull_observations):**
1. Load integration config and auth credentials from Redis/Gundi API
2. Authenticate with Ctrack Crystal (login + token refresh)
3. Fetch vehicle list, then iterate vehicles with concurrency control (semaphore)
4. For each vehicle: fetch trips, get detailed trip summaries, extract observations
5. Transform observations and send to Gundi in batches of 200
6. Persist state (last update time, processed trip IDs) in Redis per vehicle

**State management:** `IntegrationStateManager` in `services/state.py` stores per-integration, per-action, per-source state in Redis. Used to track cursors and avoid reprocessing.

**Retry strategy:** The Ctrack client (`datasource/ctrackcrystal/client.py`) retries on 429 (respects Retry-After header), 5xx, and read timeouts with backoff. Max 3 attempts per request.

## Key Conventions

- Python 3.10, pydantic v1 (1.10.x) — not v2
- Async throughout: all action handlers and service calls are `async def`
- Tests use `pytest-asyncio` and `pytest-mock`; fixtures in `app/conftest.py`
- Config models use `FieldWithUIOptions` for portal UI rendering
- Docker builds target `python:3.10-slim`; CI runs on GitHub Actions
- Dependencies pinned via `pip-tools` (`*.in` files compiled to `requirements.txt`)
