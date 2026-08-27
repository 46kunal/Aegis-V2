# Aegis V2

Aegis V2 is a digital twin security platform for vulnerability assessment, asset discovery, attack-path analysis, and report generation. It combines a FastAPI backend, a React frontend, PostgreSQL, Redis, Celery workers, nmap scanning, and vulnerability intelligence from NVD and CISA KEV.

## What it does

The project is designed to support an end-to-end assessment workflow:

- Discover and manage assets
- Run scan jobs against targets and track their status
- Enrich findings with vulnerability intelligence
- Build topology and attack-path views from discovered data
- Generate downloadable reports for completed scans
- Present a dashboard summary for operational visibility

## Tech Stack

- Backend: FastAPI, SQLAlchemy, Alembic, Celery, Redis, psycopg2
- Scanner and enrichment: nmap, NVD API, CISA KEV feed
- Frontend: React, Vite, React Router, React Flow, Axios, Tailwind CSS
- Infrastructure: PostgreSQL, Redis, Nginx, Docker Compose

## Repository Layout

- `backend/` - FastAPI service, workers, models, migrations, and scanner logic
- `frontend/` - React single-page application
- `docker-compose.yml` - Local multi-service runtime
- `nginx/` - Reverse proxy configuration
- `generated-reports/` - Local report output directory

## Core Features

### Authentication

- User registration, login, token refresh, and profile lookup
- Dev-mode auth bypass for local development
- Browser token storage and refresh flow on the frontend

### Asset Management

- Asset inventory API
- Asset discovery from scan results
- Bulk updates and asset scoping
- Asset listing and clearing operations

### Scan Orchestration

- Create, list, retry, cancel, and inspect scan jobs
- Celery-backed scan execution
- Stale-scan timeout handling on backend startup and in a periodic cleanup loop

### Vulnerability Intelligence

- nmap XML parsing
- CVE enrichment from NVD
- Known Exploited Vulnerabilities enrichment from CISA KEV
- Cached vulnerability metadata in the database

### Risk, Topology, and Attack Analysis

- Risk recomputation and asset risk views
- Topology graph generation and rebuild
- Attack simulation, chains, replay, metrics, and impact endpoints

### Reporting and Dashboard

- Dashboard summary aggregation
- Report generation per scan
- Report download endpoint

## Backend Architecture

The FastAPI application is assembled in `backend/app/main.py` and mounts the major feature routers for auth, assets, dashboard, reports, risk, attack, scans, and topology.

At startup, the backend also performs operational work:

- Refreshes the CISA KEV catalog
- Cleans up stale scans
- Starts a background loop that repeats stale-scan cleanup every 5 minutes

The main service layers are organized around these responsibilities:

- `backend/app/routes/` - HTTP API endpoints
- `backend/app/services/` - Business logic and orchestration
- `backend/app/scanner/` - nmap parsing and vulnerability data clients
- `backend/app/workers/` - Celery tasks and worker configuration
- `backend/app/models/` - Database models
- `backend/app/schemas/` - Request and response schemas

## Frontend Overview

The frontend is a functioning SPA with:

- Login and registration screens
- Protected application routes
- Dashboard, assets, scans, findings, reports, topology, and settings pages
- API base URL override for local development
- Token persistence and automatic refresh handling

The frontend uses React Flow for the topology visualization and a browser-based auth flow backed by the API.

## Local Setup

### Prerequisites

- Python 3.11 or newer
- Node.js 18 or newer
- Docker and Docker Compose
- nmap installed on the host or available in the runtime image

### Environment

Copy the example environment file and adjust values for your machine:

- `.env.example`
- `backend/.env.example`

Do not commit `.env`. The repository already ignores it.

Important settings include:

- `DATABASE_URL`
- `REDIS_URL`
- `SECRET_KEY`
- `CORS_ORIGINS`
- `PUBLIC_BASE_URL`
- `NVD_API_KEY` if you want higher NVD rate limits

### Docker Compose

Bring up the full stack:

```bash
docker compose up --build
```

This starts:

- PostgreSQL
- Redis
- Backend API
- Celery worker
- Frontend build container
- Nginx reverse proxy

### Makefile Commands

- `make install-backend` - create the backend virtual environment and install Python dependencies
- `make install-frontend` - install frontend dependencies
- `make test-backend` - run backend tests
- `make test-frontend` - run frontend tests
- `make test` - run both test suites
- `make build-backend` - compile backend Python modules
- `make build-frontend` - build the frontend bundle
- `make compose-up` - start the Docker stack
- `make compose-down` - stop the Docker stack and remove volumes

### Backend Local Run

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/uvicorn app.main:app --reload
```

### Frontend Local Run

```bash
cd frontend
npm install
npm run dev
```

## API Surface

The backend exposes these main endpoint groups:

- `/health`
- `/api/auth/*`
- `/api/assets/*`
- `/api/scans/*`
- `/api/dashboard/*`
- `/api/reports/*`
- `/api/risk/*`
- `/api/attack/*`
- `/api/topology/*`

## Implementation Status

The project is well beyond a scaffold. The core product flow is implemented and usable for a local demo or internal environment.

### Implemented

- Backend application wiring and middleware
- Authentication flow with tokens and dev mode support
- Asset inventory and discovery APIs
- Scan orchestration and scan status lifecycle
- Celery worker integration
- nmap parsing and vulnerability enrichment helpers
- Dashboard aggregation
- Topology graph endpoints and frontend visualization
- Attack analysis endpoints and UI surface
- Report generation and download flow
- Frontend routing, auth state, protected routes, and main pages
- Docker Compose based local deployment

### Partially implemented or thin

- The settings page is mostly client-local API override and profile display rather than full server-side settings management
- Report browsing is limited; the UI generates reports from a scan UUID rather than acting as a full report archive
- Some backend namespaces are present as scaffolding or package markers
- Risk and attack capabilities are stronger on the backend than in dedicated frontend navigation surfaces

### Current assessment

Roughly 75-85% of the intended MVP looks implemented, depending on how you count product polish versus core capability. The backend and primary user workflows are present; what remains is mostly integration polish, UI coverage for every backend capability, and hardening for production use.

## Security Notes

- Keep `.env` out of git
- Treat `SECRET_KEY`, database passwords, and API keys as secrets
- Set `DEV_MODE=false` outside local development
- Add an `NVD_API_KEY` if you need higher NVD request throughput

## Notes For Contributors

- The repository already ignores common generated artifacts such as `frontend/node_modules/`, `frontend/dist/`, `generated-reports/`, `dump.rdb`, and Python caches
- Backend and frontend test suites exist, so verify behavior with tests after making changes
- Some code paths depend on Postgres, Redis, Celery, and nmap, so full functionality requires those services
