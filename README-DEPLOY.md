Hickory DNS — Control API + UI (scaffold)

This workspace contains a scaffold for a new Control API and web UI to manage multi-DNS / GeoDNS features.

Quick start (docker-compose):

1. Build and run:

```bash
docker compose build
docker compose up
```

2. Open UI: http://localhost:3000
3. API: http://localhost:8080/api/v1/
4. Metrics: http://localhost:8080/metrics

What I scaffolded:
- `crates/control_api`: Rust actix-web control API skeleton with `servers`, `zones`, `health`, and `/metrics`.
- `web/ui`: Minimal React (Vite) UI with Admin and User panels (placeholders).
- `docker-compose.yml` to run both services together.

Next recommended steps:
- Integrate the existing DNS core from the repo into `control_api` as a library crate and expose control hooks.
- Implement GeoIP-based routing (e.g., MaxMind DB or IP geolocation service) in a `geodns` module.
- Implement multi-DNS orchestration: RPC, remote agent, or management plane to push config to named servers.
- Add persistent storage (Postgres / SQLite) for servers/zones and migrations.
- Implement authentication/authorization (OAuth2 / JWT) for Admin vs User roles.
- Harden Docker images and create CI/CD pipeline.

If you want, I can now:
- Wire the repo's existing DNS core into `control_api` as a library and add endpoints to control forwarding/caching/authoritative features.
- Implement GeoDNS routing and a simple simulation test harness.
- Add auth and RBAC for Admin/User.

Tell me which of the above to do next and I'll continue.
