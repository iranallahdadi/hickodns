Hickory DNS — Control Plane & UI — Design, Schema, and Deployment

Summary
- Control API (Rust / actix-web) provides management for servers, zones, agents, GeoDNS rules, and authentication.
- Agent (Rust) registers to control plane and heartbeats.
- GeoDNS crate wraps MaxMind DB lookups for country-based routing.
- React UI (Vite) provides Admin and User panels with login and basic management.
- Postgres is used for persistence. Docker Compose provided for local dev.

Project structure (key parts)
- crates/control_api: Control plane API (auth, DB, agent registration, placeholders for DNS core integration)
- crates/geodns: GeoIP lookup wrapper (MaxMind DB)
- crates/agent: Simple agent binary that registers and heartbeats
- web/ui: React-based UI (Admin + User panels)
- docker-compose.yml: local dev stack (control_api, ui, db)
- .github/workflows/ci.yml: CI build for backend, agent and frontend

Key Rust modules and responsibilities
- control_api/src/main.rs
  - DB pool (sqlx/PgPool), basic runtime migrations
  - JWT-based auth (login, create_user)
  - Endpoints: servers, zones, agents (register/heartbeat), georules (stub)
  - Prometheus metrics via `actix-web-prom`
  - Placeholders for: hickory-server integration, config push to agents, GeoDNS rule engine
- geodns: simple MaxMind-based country lookup API to be used by the routing engine
- agent: demo agent that registers and posts heartbeats to the control plane

API design (selected endpoints)
- POST /api/v1/auth/login { username, password } -> { token }
- POST /api/v1/users { username, password } -> create user (returns id)
- GET /api/v1/servers -> list servers (requires auth)
- POST /api/v1/servers { name, address, region } -> create server (admin)
- GET /api/v1/zones -> list zones
- POST /api/v1/zones { domain } -> create zone
- POST /api/v1/agents/register { name, addr } -> register agent
- POST /api/v1/agents/heartbeat { name, addr } -> record heartbeat
- GET /metrics -> Prometheus metrics

Database schema (implemented as lightweight CREATE TABLEs)
- users(id UUID PK, username TEXT UNIQUE, password_hash TEXT, role TEXT)
- servers(id UUID PK, name TEXT, address TEXT, region TEXT)
- zones(id UUID PK, domain TEXT, owner UUID)
- records(id UUID PK, zone_id UUID FK -> zones(id), name TEXT, type TEXT, value TEXT, ttl INT)
- agents(id UUID PK, name TEXT, addr TEXT, last_heartbeat TIMESTAMP WITH TIME ZONE)
- georules(id UUID PK, zone_id UUID FK -> zones(id), match_type TEXT, match_value TEXT, target TEXT)

Security and hardening notes
- JWT secret configurable via `JWT_SECRET` env var
- Passwords hashed using Argon2
- Control API Docker image runs as non-root user `app`
- In production: use strong JWT secret, TLS termination, rate limiting, and audit logging

Deployment (quick local with Docker Compose)
1. Build and run:

```bash
docker compose build
docker compose up
```

2. UI: http://localhost:3000
3. API: http://localhost:8080
4. Metrics: http://localhost:8080/metrics

Kubernetes
- The repo contains a minimal `k8s/` directory (if present) with example manifests. For production, convert to Helm charts or kustomize and configure TLS, Ingress, and resource limits.

Next recommended work (prioritized)
1. Integrate `crates/server` (Hickory DNS core) into `control_api` so control plane can spawn/manage DNS nodes and serve DNS queries itself where required. Implement code to programmatically start/stop server instances using `hickory-server` library.
2. Implement GeoDNS engine that consumes `geodns` lookups and evaluates rules in query path, with caching and telemetry for routing decisions.
3. Implement secure config push to agents (gRPC or mutual-TLS HTTPS) and agent-side config applyers.
4. Implement RBAC UI (Admin vs User), enforce ownership checks for zone/record operations.
5. Add full SQL migrations and integrate `sqlx` migrations, or a migration tool (refinery, barrel, or standalone SQL files).
6. Harden images further (distroless/baseimage, smaller toolchain builds) and add vulnerability scanning to CI.

If you'd like, I can continue and implement the next priority: full `hickory-server` integration and GeoDNS engine with tests and rollout strategy.
