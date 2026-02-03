use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, http::header};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use log::{info, warn};
use tokio_postgres::{NoTls, Client as PgClient};
use actix_web_prom::PrometheusMetricsBuilder;
use prometheus::{TextEncoder, Encoder, gather};
use uuid::Uuid;
use std::collections::HashMap;
use std::process::Command;
use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, encode, decode, TokenData};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, PasswordVerifier, PasswordHash}};
use rand_core::OsRng;
use chrono::TimeZone;

#[derive(Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct ServerInfo {
    id: String,
    name: String,
    address: String,
    region: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ZoneRecord {
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct Zone {
    id: String,
    domain: String,
    records: Vec<ZoneRecord>,
}

#[derive(Clone)]
struct AppState {
    db: std::sync::Arc<PgClient>,
    jwt_secret: String,
}

struct GeoState {
    db: Option<geodns::GeoDB>,
}

#[derive(Clone)]
struct FullState {
    inner: AppState,
    geo: std::sync::Arc<tokio::sync::Mutex<GeoState>>,
    processes: std::sync::Arc<tokio::sync::Mutex<HashMap<String, std::process::Child>>>,
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status":"ok"}))
}

async fn migrate_db(client: &PgClient) -> Result<(), tokio_postgres::Error> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS servers (id UUID PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, region TEXT);
         CREATE TABLE IF NOT EXISTS zones (id UUID PRIMARY KEY, domain TEXT NOT NULL, owner UUID);
         CREATE TABLE IF NOT EXISTS records (id UUID PRIMARY KEY, zone_id UUID REFERENCES zones(id) ON DELETE CASCADE, name TEXT, type TEXT, value TEXT, ttl INT);
         CREATE TABLE IF NOT EXISTS agents (id UUID PRIMARY KEY, name TEXT, addr TEXT, last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT now(), token_hash TEXT);
         CREATE TABLE IF NOT EXISTS georules (id UUID PRIMARY KEY, zone_id UUID REFERENCES zones(id) ON DELETE CASCADE, match_type TEXT, match_value TEXT, target TEXT);",
    ).await?;
    // Backfill: ensure token_hash column exists for older DBs
    client.batch_execute("ALTER TABLE agents ADD COLUMN IF NOT EXISTS token_hash TEXT;").await.ok();
    Ok(())
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

async fn login(body: web::Json<LoginRequest>, data: web::Data<AppState>) -> impl Responder {
    if let Ok(row) = (&*data.db).query_one("SELECT id::text, password_hash, role FROM users WHERE username = $1", &[&body.username]).await {
        let id_str: String = row.get(0);
        let id = id_str.clone();
        let password_hash: String = row.get(1);
        let role: Option<String> = row.get(2);
        if let Ok(hash) = PasswordHash::new(&password_hash) {
            if Argon2::default().verify_password(body.password.as_bytes(), &hash).is_ok() {
                let exp = (chrono::Utc::now() + chrono::Duration::hours(8)).timestamp() as usize;
                let claims = Claims { sub: id.to_string(), role: role.clone().unwrap_or("user".to_string()), exp };
                let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(data.jwt_secret.as_bytes())).unwrap();
                return HttpResponse::Ok().json(LoginResponse { token });
            }
        }
    }
    HttpResponse::Unauthorized().finish()
}

async fn create_user(req: web::Json<LoginRequest>, data: web::Data<AppState>) -> impl Responder {
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(req.password.as_bytes(), &salt).unwrap().to_string();
    let id = Uuid::new_v4();
    let role = "user";
    // pass a UUID directly to avoid parameter serialization errors
    let id_str = id.to_string();
    let res = (&*data.db).execute("INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)", &[&id_str, &req.username, &password_hash, &role]).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => {
            warn!("create_user error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

fn auth_from_header(req: &HttpRequest, secret: &str) -> Option<TokenData<Claims>> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            if s.starts_with("Bearer ") {
                let token = &s[7..];
                if let Ok(data) = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()) {
                    return Some(data);
                }
            }
        }
    }
    None
}

async fn list_servers(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if auth_from_header(&req, &data.jwt_secret).is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let rows = (&*data.db).query("SELECT id::text, name, address, region FROM servers", &[]).await.unwrap_or_default();
    let servers: Vec<ServerInfo> = rows.into_iter().map(|r| ServerInfo { id: r.get::<usize, String>(0), name: r.get(1), address: r.get(2), region: r.get(3) }).collect();
    HttpResponse::Ok().json(servers)
}

#[derive(Deserialize)]
struct CreateServerReq {
    name: String,
    address: String,
    region: Option<String>,
}

async fn create_server(body: web::Json<CreateServerReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Some(tok) = auth_from_header(&req, &data.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().finish();
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let res = (&*data.db).execute("INSERT INTO servers (id, name, address, region) VALUES ($1, $2, $3, $4)", &[&id_str, &body.name, &body.address, &body.region]).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => {
            warn!("create_server error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[derive(Deserialize)]
struct AgentRegistration {
    name: String,
    addr: String,
}

#[derive(Serialize)]
struct AgentRegisterResponse {
    id: String,
    token: String,
}

async fn agent_register(body: web::Json<AgentRegistration>, data: web::Data<AppState>) -> impl Responder {
    // create agent id and a secure token
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    // token: combine two UUIDs for sufficient entropy
    let token_plain = format!("{}{}", Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let token_hash = argon2.hash_password(token_plain.as_bytes(), &salt).unwrap().to_string();

    let res = (&*data.db).execute(
        "INSERT INTO agents (id, name, addr, token_hash) VALUES ($1, $2, $3, $4)",
        &[&id_str, &body.name, &body.addr, &token_hash]
    ).await;
    match res {
        Ok(_) => HttpResponse::Created().json(AgentRegisterResponse { id: id.to_string(), token: token_plain }),
        Err(e) => {
            warn!("agent_register error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn agent_heartbeat(body: web::Json<AgentRegistration>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    // require agent token in Authorization header
    let token = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|s| s.strip_prefix("Bearer ")).map(|s| s.to_string());
    if token.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let token = token.unwrap();

    // find agent by addr
    if let Ok(row) = (&*data.db).query_one("SELECT id::text, token_hash FROM agents WHERE addr = $1", &[&body.addr]).await {
        let id_str: String = row.get(0);
        let token_hash: Option<String> = row.get(1);
        if let Some(th) = token_hash {
            if let Ok(ph) = PasswordHash::new(&th) {
                if Argon2::default().verify_password(token.as_bytes(), &ph).is_ok() {
                    let res = (&*data.db).execute("UPDATE agents SET last_heartbeat = now() WHERE id::text = $1", &[&id_str]).await;
                    return match res {
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(e) => { warn!("agent_heartbeat error: {}", e); HttpResponse::InternalServerError().finish() }
                    };
                }
            }
        }
        return HttpResponse::Unauthorized().finish();
    }
    HttpResponse::NotFound().finish()
}

// Agent fetch config (agents call this with their token)
async fn agent_get_config(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let agent_id = path.into_inner();
    let token = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).and_then(|s| s.strip_prefix("Bearer ")).map(|s| s.to_string());
    if token.is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let token = token.unwrap();

    if let Ok(row) = (&*data.db).query_one("SELECT token_hash FROM agents WHERE id::text = $1", &[&agent_id]).await {
        let token_hash: Option<String> = row.get(0);
        if let Some(th) = token_hash {
            if let Ok(ph) = PasswordHash::new(&th) {
                if Argon2::default().verify_password(token.as_bytes(), &ph).is_ok() {
                    // In production, return signed config blob. For now, return zone list assigned to control plane.
                    let zones = (&*data.db).query("SELECT id::text, domain FROM zones", &[]).await.unwrap_or_default();
                    let z: Vec<_> = zones.into_iter().map(|r| serde_json::json!({"id": r.get::<usize, String>(0), "domain": r.get::<usize, String>(1)})).collect();
                    return HttpResponse::Ok().json(serde_json::json!({"zones": z}));
                }
            }
        }
        return HttpResponse::Unauthorized().finish();
    }
    HttpResponse::NotFound().finish()
}

// Admin-only: rotate agent token
async fn rotate_agent_token(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    // require admin role via JWT
    if let Some(tok) = auth_from_header(&req, &data.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().finish();
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }
    let agent_id = path.into_inner();
    let token_plain = format!("{}{}", Uuid::new_v4().to_string(), Uuid::new_v4().to_string());
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let token_hash = argon2.hash_password(token_plain.as_bytes(), &salt).unwrap().to_string();
    let res = (&*data.db).execute("UPDATE agents SET token_hash = $1 WHERE id::text = $2", &[&token_hash, &agent_id]).await;
    match res {
        Ok(r) => if r == 0 { HttpResponse::NotFound().finish() } else { HttpResponse::Ok().json(serde_json::json!({"token": token_plain})) },
        Err(e) => { warn!("rotate_agent_token error: {}", e); HttpResponse::InternalServerError().finish() }
    }
}

async fn list_agents(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Some(tok) = auth_from_header(&req, &data.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().finish();
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }
    let rows = (&*data.db).query("SELECT id::text, name, addr, EXTRACT(EPOCH FROM last_heartbeat) as epoch FROM agents", &[]).await.unwrap_or_default();
    let agents: Vec<_> = rows.into_iter().map(|r| {
        let id: String = r.get(0);
        let name: String = r.get(1);
        let addr: String = r.get(2);
        let epoch: f64 = r.get(3);
        let last_dt = chrono::Utc.timestamp_opt(epoch as i64, ((epoch.fract() * 1e9) as u32)).single().unwrap_or(chrono::Utc::now());
        let age = chrono::Utc::now().signed_duration_since(last_dt).num_seconds();
        let online = age < 120;
        serde_json::json!({"id": id, "name": name, "addr": addr, "last_heartbeat": last_dt.to_rfc3339(), "online": online})
    }).collect();
    HttpResponse::Ok().json(agents)
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct StartDnsReq {
    id: String,
    bind: String,
}

async fn start_dns_server(body: web::Json<StartDnsReq>, data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    // require admin
    if let Some(tok) = auth_from_header(&req, &data.inner.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().body("admin role required");
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }

    let server_id = body.id.clone();
    // create temp zone dir
    let zonedir = format!("/tmp/hickory_control/{}", server_id);
    if let Err(e) = std::fs::create_dir_all(&zonedir) {
        warn!("failed create zonedir {}: {}", zonedir, e);
        return HttpResponse::InternalServerError().body("failed to create zonedir");
    }

    // write zone files from DB
    let zones = (&*data.inner.db).query("SELECT id::text, domain FROM zones", &[]).await.unwrap_or_default();
    for z in zones.into_iter() {
        let zid: String = z.get(0);
        let domain: String = z.get(1);
        let fname = format!("{}/{}.zone", zonedir, domain.replace('.', "_"));
        if let Ok(mut f) = std::fs::File::create(&fname) {
            use std::io::Write;
            let soa = format!("@ 3600 IN SOA ns.{} hostmaster.{} 1 3600 3600 604800 3600\n", domain, domain);
            let _ = f.write_all(soa.as_bytes());
            let recs = (&*data.inner.db).query("SELECT name, type, value, ttl FROM records WHERE zone_id::text = $1", &[&zid]).await.unwrap_or_default();
            for r in recs {
                let name: String = r.get(0);
                let typ: String = r.get(1);
                let value: String = r.get(2);
                let ttl: i32 = r.get(3);
                let rr = format!("{} {} IN {} {}\n", if name.is_empty() { "@" } else { &name }, ttl, typ, value);
                let _ = f.write_all(rr.as_bytes());
            }
        }
    }

    let bin = std::env::var("HICKORY_DNS_BIN").unwrap_or_else(|_| "./target/debug/hickory-dns".to_string());
    let port_arg = if body.bind.is_empty() { "0".to_string() } else { body.bind.clone() };
    let mut cmd = Command::new(bin);
    cmd.arg("-d").arg(format!("--zonedir={}", zonedir)).arg(format!("--port={}", port_arg));

    match cmd.spawn() {
        Ok(child) => {
            let mut procs = data.processes.lock().await;
            procs.insert(server_id.clone(), child);
            HttpResponse::Ok().json(serde_json::json!({"status":"started","server_id": server_id}))
        }
        Err(e) => {
            warn!("failed spawning dns process: {}", e);
            HttpResponse::InternalServerError().body("failed to spawn dns")
        }
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct StopDnsReq {
    id: String,
}
async fn stop_dns_server(body: web::Json<StopDnsReq>, data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    // require admin via JWT
    if let Some(tok) = auth_from_header(&req, &data.inner.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().body("admin role required");
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }

    let server_id = body.id.clone();
    let mut procs = data.processes.lock().await;
    if let Some(mut child) = procs.remove(&server_id) {
        match child.kill() {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status":"stopped","server_id": server_id})),
            Err(e) => {
                warn!("failed killing process {}: {}", server_id, e);
                HttpResponse::InternalServerError().body("failed to stop process")
            }
        }
    } else {
        HttpResponse::NotFound().body("server not found or not running")
    }
}

#[derive(Deserialize)]
struct CreateGeoRuleReq {
    zone_id: String,
    match_type: String,
    match_value: String,
    target: String,
}

async fn create_georule(body: web::Json<CreateGeoRuleReq>, data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    if auth_from_header(&req, &data.inner.jwt_secret).is_none() { return HttpResponse::Unauthorized().finish(); }
    let id = Uuid::new_v4();
    let zone_uuid = match Uuid::parse_str(&body.zone_id) {
        Ok(z) => z,
        Err(_) => return HttpResponse::BadRequest().body("invalid zone_id"),
    };
    let id_str = id.to_string();
    let zone_str = zone_uuid.to_string();
    let res = (&*data.inner.db).execute("INSERT INTO georules (id, zone_id, match_type, match_value, target) VALUES ($1, $2, $3, $4, $5)", &[&id_str, &zone_str, &body.match_type, &body.match_value, &body.target]).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => { warn!("create_georule error: {}", e); HttpResponse::InternalServerError().finish() }
    }
}

async fn list_georules(data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    if auth_from_header(&req, &data.inner.jwt_secret).is_none() { return HttpResponse::Unauthorized().finish(); }
    let rows = (&*data.inner.db).query("SELECT id::text, zone_id::text, match_type, match_value, target FROM georules", &[]).await.unwrap_or_default();
    let out: Vec<_> = rows.into_iter().map(|r| serde_json::json!({"id": r.get::<usize, String>(0), "zone_id": r.get::<usize, String>(1), "match_type": r.get::<usize, String>(2), "match_value": r.get::<usize, String>(3), "target": r.get::<usize, String>(4)})).collect();
    HttpResponse::Ok().json(out)
}

#[derive(Deserialize)]
struct CreateZoneReq {
    domain: String,
}

async fn list_zones(data: web::Data<AppState>, _req: HttpRequest) -> impl Responder {
    // show all zones if admin, otherwise only user-owned zones
    let mut q = "SELECT id::text, domain, owner::text FROM zones".to_string();
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![];
    let req = _req;
    if let Some(tok) = auth_from_header(&req, &data.jwt_secret) {
        if tok.claims.role != "admin" {
            q = "SELECT id::text, domain, owner::text FROM zones WHERE owner::text = $1".to_string();
            let owner_str = tok.claims.sub.clone();
            params.push(&owner_str);
            let rows = (&*data.db).query(q.as_str(), params.as_slice()).await.unwrap_or_default();
            let zones: Vec<Zone> = rows.into_iter().map(|r| Zone { id: r.get::<usize, String>(0), domain: r.get(1), records: vec![] }).collect();
            return HttpResponse::Ok().json(zones);
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }
    let rows = (&*data.db).query(q.as_str(), &[]).await.unwrap_or_default();
    let zones: Vec<Zone> = rows.into_iter().map(|r| Zone { id: r.get::<usize, String>(0), domain: r.get(1), records: vec![] }).collect();
    HttpResponse::Ok().json(zones)
}

async fn create_zone(body: web::Json<CreateZoneReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if auth_from_header(&req, &data.jwt_secret).is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let tok = auth_from_header(&req, &data.jwt_secret).unwrap();
    let owner = tok.claims.sub.clone();
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let safe_domain = body.domain.replace("'", "''");
    let safe_owner = owner.replace("'", "''");
    let insert_sql = format!("INSERT INTO zones (id, domain, owner) VALUES ('{}', '{}', '{}')", id_str, safe_domain, safe_owner);
    info!("create_zone (formatted SQL): {}", insert_sql);
    let res = (&*data.db).execute(insert_sql.as_str(), &[]).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => {
            warn!("create_zone error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[derive(Deserialize)]
struct GeoResolveRequest {
    zone_id: String,
    client_ip: String,
}

/// Resolve a DNS response for a zone based on client's geographic location.
/// Uses GeoRules to determine which target address to return.
async fn resolve_by_geo(body: web::Json<GeoResolveRequest>, data: web::Data<FullState>) -> impl Responder {
    // Parse client IP
    let client_ip = match body.client_ip.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return HttpResponse::BadRequest().body("invalid client IP"),
    };

    // Fetch georules for this zone from DB
    let rows = (&*data.inner.db)
        .query(
            "SELECT id::text, match_type, match_value, target FROM georules WHERE zone_id::text = $1",
            &[&body.zone_id],
        )
        .await
        .unwrap_or_default();

    let rules: Vec<geodns::GeoRule> = rows
        .into_iter()
        .map(|r| geodns::GeoRule {
            id: r.get::<usize, String>(0),
            match_type: r.get::<usize, String>(1),
            match_value: r.get::<usize, String>(2),
            target: r.get::<usize, String>(3),
        })
        .collect();

    // Get GeoIP DB from state
    let geo_state = data.geo.lock().await;
    let db = geo_state.db.as_ref().cloned();

    // Create rule engine and evaluate
    let mut engine = geodns::GeoRuleEngine::new(db);
    engine.set_rules(rules);

    // Evaluate and return target
    match engine.evaluate(client_ip) {
        Some(target) => HttpResponse::Ok().json(serde_json::json!({"target": target})),
        None => HttpResponse::Ok().json(serde_json::json!({"target": None::<String>, "message": "no matching geo rule"})),
    }
}

// Placeholder: function to push configuration to agents (secure HTTPS/gRPC in production)
#[allow(dead_code)]
async fn push_config_to_agent(_agent_id: &str) {
    // TODO: implement secure config push
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ConfigPushRequest {
    agent_id: String,
    zone_id: String,
    zone_config: serde_json::Value,
}

#[derive(Serialize)]
struct ConfigPushResponse {
    success: bool,
    message: String,
}

/// Push DNS zone configuration to an agent securely (mTLS placeholder)
/// In production: use rustls with client certificates for authentication
async fn push_config_to_agents(
    body: web::Json<ConfigPushRequest>,
    data: web::Data<FullState>,
    req: HttpRequest,
) -> impl Responder {
    // Verify admin role
    if let Some(tok) = auth_from_header(&req, &data.inner.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().body("admin role required");
        }
    } else {
        return HttpResponse::Unauthorized().finish();
    }

    // Fetch agent details from DB
    let rows = (&*data.inner.db)
        .query("SELECT id::text, addr FROM agents WHERE id::text = $1", &[&body.agent_id])
        .await
        .unwrap_or_default();

    if rows.is_empty() {
        return HttpResponse::NotFound().body("agent not found");
    }

    let _agent_addr: String = rows[0].get(1);

    // In production, this would:
    // 1. Use mTLS to securely connect to agent at agent_addr
    // 2. Sign config with control plane private key
    // 3. Send config blob to agent
    // 4. Verify agent signature on acknowledgment

    // For now, log the config push intention
    info!(
        "Config push scheduled for agent {} with zone {}",
        body.agent_id, body.zone_id
    );

    HttpResponse::Ok().json(ConfigPushResponse {
        success: true,
        message: "config push queued".to_string(),

    })
}
    // ============================================================================
    // RECORDS CRUD ENDPOINTS
    // ============================================================================

    #[derive(Deserialize)]
    struct CreateRecordReq {
        name: String,
        record_type: String,
        value: String,
        ttl: u32,
    }

    #[derive(Serialize, Clone)]
    struct RecordResponse {
        id: String,
        zone_id: String,
        name: String,
        record_type: String,
        value: String,
        ttl: u32,
    }

    async fn create_record(
        zone_id: web::Path<String>,
        body: web::Json<CreateRecordReq>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        if auth_from_header(&req, &data.jwt_secret).is_none() {
            return HttpResponse::Unauthorized().finish();
        }
    
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let zone_id_str = zone_id.into_inner();
    
        let safe_name = body.name.replace("'", "''");
        let safe_value = body.value.replace("'", "''");
        let insert_sql = format!("INSERT INTO records (id, zone_id, name, type, value, ttl) VALUES ('{}', '{}', '{}', '{}', '{}', {})", id_str, zone_id_str, safe_name, body.record_type, safe_value, body.ttl);
        info!("create_record (formatted SQL): {}", insert_sql);
        let res = (&*data.db).execute(insert_sql.as_str(), &[]).await;
    
        match res {
            Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
            Err(e) => {
                warn!("create_record error: {}", e);
                HttpResponse::InternalServerError().finish()
            }
        }
    }

    async fn list_records(
        zone_id: web::Path<String>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        if auth_from_header(&req, &data.jwt_secret).is_none() {
            return HttpResponse::Unauthorized().finish();
        }
    
        let zone_id_str = zone_id.into_inner();
        let rows = (&*data.db)
            .query(
                "SELECT id::text, zone_id::text, name, type, value, ttl FROM records WHERE zone_id::text = $1 ORDER BY name",
                &[&zone_id_str]
            )
            .await
            .unwrap_or_default();
    
        let records: Vec<RecordResponse> = rows.into_iter().map(|r| RecordResponse {
            id: r.get::<usize, String>(0),
            zone_id: r.get::<usize, String>(1),
            name: r.get::<usize, String>(2),
            record_type: r.get::<usize, String>(3),
            value: r.get::<usize, String>(4),
            ttl: r.get::<usize, i32>(5) as u32,
        }).collect();
    
        HttpResponse::Ok().json(records)
    }

    #[derive(Deserialize)]
    struct UpdateRecordReq {
        name: Option<String>,
        record_type: Option<String>,
        value: Option<String>,
        ttl: Option<u32>,
    }

    async fn update_record(
        path: web::Path<(String, String)>,
        body: web::Json<UpdateRecordReq>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        if auth_from_header(&req, &data.jwt_secret).is_none() {
            return HttpResponse::Unauthorized().finish();
        }
    
        let (zone_id, record_id) = path.into_inner();
    
        // Build dynamic update query
        let mut updates = vec![];
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![];
    
        let mut param_idx = 1;
        if let Some(ref name) = body.name {
            updates.push(format!("name = ${}", param_idx));
            params.push(name);
            param_idx += 1;
        }
        if let Some(ref record_type) = body.record_type {
            updates.push(format!("type = ${}", param_idx));
            params.push(record_type);
            param_idx += 1;
        }
        if let Some(ref value) = body.value {
            updates.push(format!("value = ${}", param_idx));
            params.push(value);
            param_idx += 1;
        }
        let ttl_str;
        if let Some(ttl) = body.ttl {
            ttl_str = ttl.to_string();
            updates.push(format!("ttl = ${}", param_idx));
            params.push(&ttl_str);
            param_idx += 1;
        }
    
        if updates.is_empty() {
            return HttpResponse::BadRequest().body("no fields to update");
        }
    
        let query = format!(
            "UPDATE records SET {} WHERE id::text = ${} AND zone_id::text = ${}",
            updates.join(", "), param_idx, param_idx + 1
        );
    
        params.push(&record_id);
        params.push(&zone_id);
    
        let res = (&*data.db).execute(query.as_str(), params.as_slice()).await;
    
        match res {
            Ok(count) => {
                if count == 0 {
                    HttpResponse::NotFound().finish()
                } else {
                    HttpResponse::Ok().finish()
                }
            }
            Err(e) => {
                warn!("update_record error: {}", e);
                HttpResponse::InternalServerError().finish()
            }
        }
    }

    async fn delete_record(
        path: web::Path<(String, String)>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        if auth_from_header(&req, &data.jwt_secret).is_none() {
            return HttpResponse::Unauthorized().finish();
        }
    
        let (zone_id, record_id) = path.into_inner();
    
        let res = (&*data.db).execute(
            "DELETE FROM records WHERE id::text = $1 AND zone_id::text = $2",
            &[&record_id, &zone_id]
        ).await;
    
        match res {
            Ok(count) => {
                if count == 0 {
                    HttpResponse::NotFound().finish()
                } else {
                    HttpResponse::Ok().finish()
                }
            }
            Err(e) => {
                warn!("delete_record error: {}", e);
                HttpResponse::InternalServerError().finish()
            }
        }
    }
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    info!("Starting control API...");

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "host=db user=postgres password=password dbname=hickory".to_string());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "replace_with_a_super_secret".to_string());

    let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await.expect("cannot connect to db");
    // spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            warn!("postgres connection error: {}", e);
        }
    });
    migrate_db(&client).await.expect("db migrate failed");

    // Bootstrap admin user if environment variables are set
    if let (Ok(admin_user), Ok(admin_password)) = (std::env::var("ADMIN_USERNAME"), std::env::var("ADMIN_PASSWORD")) {
        // check if a user exists with that username
        if let Ok(rows) = (&client).query("SELECT id::text, password_hash FROM users WHERE username = $1 LIMIT 1", &[&admin_user]).await {
            if rows.is_empty() {
                // create new admin
                let mut rng = OsRng;
                let salt = SaltString::generate(&mut rng);
                let argon2 = Argon2::default();
                let password_hash = argon2.hash_password(admin_password.as_bytes(), &salt).unwrap().to_string();
                let id = Uuid::new_v4();
                let id_str = id.to_string();
                let role = "admin";
                match (&client).execute("INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)", &[&id_str, &admin_user, &password_hash, &role]).await {
                    Ok(_) => info!("Bootstrapped admin user '{}'", admin_user),
                    Err(e) => warn!("Failed to create admin user '{}': {}", admin_user, e),
                }
            } else {
                // user exists, ensure password_hash looks valid (contains $argon2)
                let existing_hash: String = rows[0].get(1);
                if !existing_hash.starts_with("$argon2") {
                    let mut rng = OsRng;
                    let salt = SaltString::generate(&mut rng);
                    let argon2 = Argon2::default();
                    let password_hash = argon2.hash_password(admin_password.as_bytes(), &salt).unwrap().to_string();
                    match (&client).execute("UPDATE users SET password_hash = $1 WHERE username = $2", &[&password_hash, &admin_user]).await {
                        Ok(_) => info!("Updated admin user '{}' password hash", admin_user),
                        Err(e) => warn!("Failed to update admin user '{}': {}", admin_user, e),
                    }
                } else {
                    info!("Admin user already exists, skipping bootstrap");
                }
            }
        } else {
            warn!("Failed to query for admin user during bootstrap");
        }
    }

    let app_state = AppState { db: std::sync::Arc::new(client), jwt_secret: jwt_secret.clone() };

    // Load GeoIP DB if provided
    let geo_db = std::env::var("GEOIP_DB_PATH").ok().and_then(|p| {
        std::fs::read(p).ok().and_then(|b| geodns::GeoDB::open_from_bytes(b).ok())
    });

    let full_state = FullState { inner: app_state.clone(), geo: std::sync::Arc::new(tokio::sync::Mutex::new(GeoState { db: geo_db })), processes: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())) };

    // Prometheus metrics middleware
    let prometheus = PrometheusMetricsBuilder::new("control_api").endpoint("/metrics").build().expect("prometheus builder");

    let app_data = web::Data::new(app_state.clone());
    let full_data = web::Data::new(full_state.clone());

        HttpServer::new(move || {
            App::new()
                .wrap(Cors::default().allow_any_origin().allow_any_method().allow_any_header())
                .wrap(prometheus.clone())
                .app_data(app_data.clone())
                .app_data(full_data.clone())
            .route("/api/v1/auth/login", web::post().to(login))
            .route("/api/v1/users", web::post().to(create_user))
            .route("/api/v1/servers", web::get().to(list_servers))
            .route("/api/v1/servers", web::post().to(create_server))
                    .route("/api/v1/zones", web::get().to(list_zones))
                    .route("/api/v1/zones", web::post().to(create_zone))
            .route("/api/v1/agents/register", web::post().to(agent_register))
                            .route("/api/v1/agents/heartbeat", web::post().to(agent_heartbeat))
                            .route("/api/v1/agents", web::get().to(list_agents))
            .route("/api/v1/dns/start", web::post().to(start_dns_server))
            .route("/api/v1/dns/stop", web::post().to(stop_dns_server))
            .route("/api/v1/georules", web::post().to(create_georule))
            .route("/api/v1/georules", web::get().to(list_georules))
            .route("/api/v1/georules/resolve", web::post().to(resolve_by_geo))
            .route("/api/v1/config/push", web::post().to(push_config_to_agents))
            .route("/health", web::get().to(health))
            .route("/api/v1/agents/{id}/config", web::get().to(agent_get_config))
            .route("/api/v1/agents/{id}/token/rotate", web::post().to(rotate_agent_token))
            // explicit metrics handler (in addition to middleware-exposed endpoint)
            .route("/metrics", web::get().to(|| async move {
                let encoder = TextEncoder::new();
                let metric_families = gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap_or(());
                HttpResponse::Ok().content_type("text/plain; version=0.0.4").body(buffer)
            }))
                .route("/api/v1/zones/{id}/records", web::post().to(create_record))
                .route("/api/v1/zones/{id}/records", web::get().to(list_records))
                .route("/api/v1/zones/{zone_id}/records/{record_id}", web::put().to(update_record))
                .route("/api/v1/zones/{zone_id}/records/{record_id}", web::delete().to(delete_record))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
