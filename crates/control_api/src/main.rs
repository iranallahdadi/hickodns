use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, http::header};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use log::{info, warn};
use std::sync::Arc;
use std::collections::HashMap;
use std::process::Command;
use tokio_postgres::NoTls;
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, TokenData};
use uuid::Uuid;
use actix_cors::Cors;
use actix_web_prom::PrometheusMetricsBuilder;
use prometheus::{TextEncoder, Encoder};
use prometheus::gather;
use chrono::TimeZone;

// ============================================================================
// OpenAPI / Swagger Types
// ============================================================================

#[derive(ToSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

#[derive(ToSchema, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct ServerInfo {
    id: String,
    name: String,
    address: String,
    port: i32,
    region: Option<String>,
    enabled: bool,
    dnssec: bool,
    enable_logging: bool,
    max_cache_ttl: i32,
    min_cache_ttl: i32,
    status: Option<String>,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct ZoneRecord {
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct Zone {
    id: String,
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    records: Vec<ZoneRecord>,
}

#[derive(ToSchema, Clone, Serialize, Deserialize)]
struct ZoneWithOwner {
    id: String,
    domain: String,
    owner: String,
    zone_type: String,
    created_at: String,
}

#[derive(Clone)]
struct AppState {
    db: Arc<tokio_postgres::Client>,
    jwt_secret: String,
}

struct GeoState {
    db: Option<geodns::GeoDB>,
}

#[derive(Clone)]
struct FullState {
    inner: AppState,
    geo: Arc<tokio::sync::Mutex<GeoState>>,
    processes: Arc<tokio::sync::Mutex<HashMap<String, std::process::Child>>>,
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status":"ok"}))
}

async fn ready(data: web::Data<AppState>) -> impl Responder {
    match data.db.query("SELECT 1", &[]).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status":"ready"})),
        Err(e) => {
            warn!("database not ready: {}", e);
            HttpResponse::ServiceUnavailable().json(serde_json::json!({"status":"not ready"}))
        }
    }
}

fn validate_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() || domain.len() > 253 {
        return Err("Domain must be 1-253 characters".to_string());
    }
    if !domain.ends_with('.') {
        return Err("Domain must end with .".to_string());
    }
    let valid = domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-');
    if !valid {
        return Err("Domain contains invalid characters".to_string());
    }
    Ok(())
}

fn validate_record_type(record_type: &str) -> Result<(), String> {
    let valid_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "DS", "DNSKEY"];
    if !valid_types.contains(&record_type.to_uppercase().as_str()) {
        return Err(format!("Invalid record type: {}", record_type));
    }
    Ok(())
}

async fn migrate_db(client: &tokio_postgres::Client) -> Result<(), tokio_postgres::Error> {
    client.batch_execute(
        "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS servers (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            port INT DEFAULT 53,
            region TEXT,
            enabled BOOLEAN DEFAULT true,
            dnssec BOOLEAN DEFAULT false,
            enable_logging BOOLEAN DEFAULT true,
            max_cache_ttl INT DEFAULT 3600,
            min_cache_ttl INT DEFAULT 60,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS zones (
            id UUID PRIMARY KEY,
            domain TEXT NOT NULL,
            owner UUID REFERENCES users(id) ON DELETE SET NULL,
            zone_type TEXT NOT NULL DEFAULT 'primary',
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now(),
            UNIQUE(domain)
        );
        
        CREATE TABLE IF NOT EXISTS records (
            id UUID PRIMARY KEY,
            zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            ttl INT NOT NULL DEFAULT 3600,
            priority INT DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS agents (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            addr TEXT NOT NULL,
            last_heartbeat TIMESTAMPTZ DEFAULT now(),
            token_hash TEXT NOT NULL,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS georules (
            id UUID PRIMARY KEY,
            zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
            match_type TEXT NOT NULL,
            match_value TEXT NOT NULL,
            target TEXT NOT NULL,
            priority INT DEFAULT 0,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS acls (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
            networks TEXT NOT NULL,
            server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS rate_limits (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            queries_per_second INT DEFAULT 100,
            burst INT DEFAULT 200,
            server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS dns_views (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            match_clients TEXT NOT NULL,
            server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
            enabled BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY,
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details JSONB,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMPTZ DEFAULT now()
        );
        
        CREATE TABLE IF NOT EXISTS agent_configs (
            id UUID PRIMARY KEY,
            agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
            config_version INT NOT NULL,
            config_data JSONB NOT NULL,
            release_channel TEXT NOT NULL DEFAULT 'stable',
            is_active BOOLEAN DEFAULT false,
            created_at TIMESTAMPTZ DEFAULT now(),
            deployed_at TIMESTAMPTZ
        );
        
        CREATE INDEX IF NOT EXISTS idx_zones_owner ON zones(owner);
        CREATE INDEX IF NOT EXISTS idx_zones_domain ON zones(domain);
        CREATE INDEX IF NOT EXISTS idx_records_zone_id ON records(zone_id);
        CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(name, type);
        CREATE INDEX IF NOT EXISTS idx_georules_zone_id ON georules(zone_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_agents_enabled ON agents(enabled);",
    ).await?;
    
    client.batch_execute("ALTER TABLE agents ADD COLUMN IF NOT EXISTS token_hash TEXT;").await.ok();
    client.batch_execute("ALTER TABLE agents ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;").await.ok();
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
    expires_in: usize,
}

async fn login(body: web::Json<LoginRequest>, data: web::Data<AppState>) -> impl Responder {
    let username = body.username.trim();
    if username.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "username required"}));
    }
    
    if let Ok(row) = (&*data.db).query_one(
        "SELECT id::text, password_hash, role FROM users WHERE username = $1",
        &[&username]
    ).await {
        let id_str: String = row.get(0);
        let id = id_str.clone();
        let password_hash: String = row.get(1);
        let role: Option<String> = row.get(2);
        
        if let Ok(hash) = PasswordHash::new(&password_hash) {
            if Argon2::default().verify_password(body.password.as_bytes(), &hash).is_ok() {
                let exp = (chrono::Utc::now() + chrono::Duration::hours(8)).timestamp() as usize;
                let claims = Claims { 
                    sub: id.to_string(), 
                    role: role.clone().unwrap_or_else(|| "user".to_string()), 
                    exp 
                };
                
                match encode(&Header::default(), &claims, &EncodingKey::from_secret(data.jwt_secret.as_bytes())) {
                    Ok(token) => {
                        return HttpResponse::Ok().json(LoginResponse { token, expires_in: 28800 });
                    }
                    Err(e) => {
                        warn!("JWT encode error: {}", e);
                        return HttpResponse::InternalServerError().finish();
                    }
                }
            }
        }
    }
    HttpResponse::Unauthorized().json(serde_json::json!({"error": "invalid credentials"}))
}

async fn logout(req: HttpRequest) -> impl Responder {
    if let Some(auth) = req.headers().get("authorization") {
        if let Ok(token) = auth.to_str() {
            if token.starts_with("Bearer ") {
                return HttpResponse::Ok().json(serde_json::json!({"message": "logged out successfully"}));
            }
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"message": "no active session"}))
}

async fn get_current_user(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"})),
    };
    
    let user_id = &tok.claims.sub;
    match (&*data.db).query_opt(
        "SELECT id, username, role, created_at FROM users WHERE id = $1",
        &[user_id]
    ).await {
        Ok(Some(row)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "id": row.get::<_, String>(0),
                "username": row.get::<_, String>(1),
                "role": row.get::<_, String>(2),
                "createdAt": row.get::<_, String>(3)
            }))
        }
        Ok(None) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}))
        }
        Err(e) => {
            warn!("get_current_user error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

async fn create_user(req: web::Json<LoginRequest>, data: web::Data<AppState>) -> impl Responder {
    let username = req.username.trim();
    if username.is_empty() || username.len() < 3 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "username must be at least 3 characters"}));
    }
    if req.password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "password must be at least 8 characters"}));
    }
    
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(req.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            warn!("password hash error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to hash password"}));
        }
    };
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let role = "user";
    
    match (&*data.db).execute(
        "INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)",
        &[&id_str, &username, &password_hash, &role]
    ).await {
        Ok(_) => {
            info!("Created user: {}", username);
            HttpResponse::Created().json(serde_json::json!({"id": id.to_string(), "username": username}))
        }
        Err(e) => {
            if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                warn!("create_user error: username already exists");
                HttpResponse::Conflict().json(serde_json::json!({"error": "username already exists"}))
            } else {
                warn!("create_user error: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to create user"}))
            }
        }
    }
}

#[derive(Deserialize)]
struct UpdateUserReq {
    username: Option<String>,
    role: Option<String>,
}

async fn get_user(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let user_id = path.into_inner();
    if auth_from_header(&req, &data.jwt_secret).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    
    match (&*data.db).query(
        "SELECT id, username, role, created_at FROM users WHERE id = $1",
        &[&user_id]
    ).await {
        Ok(rows) => {
            if rows.is_empty() {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}));
            }
            let row = &rows[0];
            let id: String = row.get(0);
            let username: String = row.get(1);
            let role: String = row.get(2);
            let created_at: String = row.get(3);
            HttpResponse::Ok().json(serde_json::json!({
                "id": id,
                "username": username,
                "role": role,
                "createdAt": created_at
            }))
        }
        Err(e) => {
            warn!("get_user error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

async fn list_users(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"})),
    };
    
    // Only admins can list all users
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    
    match (&*data.db).query(
        "SELECT id, username, role, created_at FROM users ORDER BY username",
        &[]
    ).await {
        Ok(rows) => {
            let users: Vec<_> = rows.into_iter().map(|r| {
                serde_json::json!({
                    "id": r.get::<_, String>(0),
                    "username": r.get::<_, String>(1),
                    "role": r.get::<_, String>(2),
                    "createdAt": r.get::<_, String>(3)
                })
            }).collect();
            HttpResponse::Ok().json(users)
        }
        Err(e) => {
            warn!("list_users error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "database error"}))
        }
    }
}

async fn update_user(path: web::Path<String>, body: web::Json<UpdateUserReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let user_id = path.into_inner();
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"})),
    };
    
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    
    if let Some(username) = &body.username {
        if username.len() < 3 {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "username must be at least 3 characters"}));
        }
        match (&*data.db).execute(
            "UPDATE users SET username = $1, updated_at = now() WHERE id::text = $2",
            &[username, &user_id]
        ).await {
            Ok(result) => {
                if result > 0 {
                    HttpResponse::Ok().json(serde_json::json!({"message": "user updated"}))
                } else {
                    HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}))
                }
            }
            Err(e) => {
                if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                    HttpResponse::Conflict().json(serde_json::json!({"error": "username already exists"}))
                } else {
                    HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to update user"}))
                }
            }
        }
    } else if let Some(role) = &body.role {
        match (&*data.db).execute(
            "UPDATE users SET role = $1, updated_at = now() WHERE id::text = $2",
            &[role, &user_id]
        ).await {
            Ok(result) => {
                if result > 0 {
                    HttpResponse::Ok().json(serde_json::json!({"message": "user updated"}))
                } else {
                    HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}))
                }
            }
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to update user: {}", e)}))
        }
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({"error": "no fields to update"}))
    }
}

async fn delete_user(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let user_id = path.into_inner();
    let tok = match auth_from_header(&req, &data.jwt_secret) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"})),
    };
    
    if tok.claims.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
    }
    
    if user_id == tok.claims.sub {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "cannot delete yourself"}));
    }
    
    match (&*data.db).execute("DELETE FROM users WHERE id::text = $1", &[&user_id]).await {
        Ok(result) => {
            if result > 0 {
                HttpResponse::Ok().json(serde_json::json!({"message": "user deleted"}))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"}))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to delete user: {}", e)}))
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
    let rows = (&*data.db).query(
        "SELECT id::text, name, address, port, region, enabled, dnssec, enable_logging, max_cache_ttl, min_cache_ttl FROM servers", 
        &[]
    ).await.unwrap_or_default();
    
    let servers: Vec<ServerInfo> = rows.into_iter().map(|r| ServerInfo {
        id: r.get(0),
        name: r.get(1),
        address: r.get(2),
        port: r.get(3),
        region: r.get(4),
        enabled: r.get(5),
        dnssec: r.get(6),
        enable_logging: r.get(7),
        max_cache_ttl: r.get(8),
        min_cache_ttl: r.get(9),
        status: None,
    }).collect();
    HttpResponse::Ok().json(servers)
}

#[derive(Deserialize)]
struct CreateServerReq {
    name: String,
    address: String,
    port: Option<i32>,
    region: Option<String>,
    enabled: Option<bool>,
    dnssec: Option<bool>,
    enable_logging: Option<bool>,
    max_cache_ttl: Option<i32>,
    min_cache_ttl: Option<i32>,
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
    let port = body.port.unwrap_or(53);
    let enabled = body.enabled.unwrap_or(true);
    let dnssec = body.dnssec.unwrap_or(false);
    let enable_logging = body.enable_logging.unwrap_or(true);
    let max_cache_ttl = body.max_cache_ttl.unwrap_or(3600);
    let min_cache_ttl = body.min_cache_ttl.unwrap_or(60);
    
    let res = (&*data.db).execute(
        "INSERT INTO servers (id, name, address, port, region, enabled, dnssec, enable_logging, max_cache_ttl, min_cache_ttl) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", 
        &[&id_str, &body.name, &body.address, &port, &body.region, &enabled, &dnssec, &enable_logging, &max_cache_ttl, &min_cache_ttl]
    ).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => {
            warn!("create_server error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn delete_server(path: web::Path<String>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if let Some(tok) = auth_from_header(&req, &data.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
        }
    } else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    let server_id = path.into_inner();
    match (&*data.db).execute("DELETE FROM servers WHERE id = $1", &[&server_id]).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Err(e) => {
            warn!("delete_server error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to delete server"}))
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
        // let last_dt = chrono::Utc.timestamp_opt(epoch as i64, ((epoch.fract() * 1e9) as u32)).single().unwrap_or(chrono::Utc::now());
        let last_dt = chrono::Utc.timestamp_opt(epoch as i64, (epoch.fract() * 1e9) as u32 ).single().unwrap_or(chrono::Utc::now());
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
    let bind_addr = if body.bind.is_empty() { "0.0.0.0".to_string() } else {
        body.bind.split(':').next().unwrap_or("0.0.0.0").to_string()
    };
    let port: u16 = if body.bind.is_empty() { 53 } else {
        body.bind.split(':').last().unwrap_or("53").parse().unwrap_or(53)
    };

    // create temp config dir
    let config_dir = format!("/tmp/hickory_control/{}", server_id);
    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        warn!("failed create config dir {}: {}", config_dir, e);
        return HttpResponse::InternalServerError().body("failed to create config dir");
    }

    // write zone files from DB
    let zones = (&*data.inner.db).query("SELECT id::text, domain FROM zones", &[]).await.unwrap_or_default();
    let mut zone_configs = String::new();
    
    for z in zones.into_iter() {
        let zid: String = z.get(0);
        let domain: String = z.get(1);
        let fname = format!("{}/{}.zone", config_dir, domain.replace('.', "_").replace("-", "_"));
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
                let rr = format!("{} {} IN {} {}\n", if name.is_empty() || name == "@" { "@" } else { &name }, ttl, typ, value);
                let _ = f.write_all(rr.as_bytes());
            }
        }
        zone_configs.push_str(&format!(
            r#"[[zones]]
zone = "{}"
zone_type = "Primary"
file = "{}.zone"

"#,
            domain.trim_end_matches('.'),
            domain.replace('.', "_").replace("-", "_")
        ));
    }

    // Generate TOML config
    let config_content = format!(
        r#"# Auto-generated config for Hickory DNS
listen_addrs_ipv4 = ["{}"]
listen_port = {}

{}

[[zones]]
zone = "localhost"
zone_type = "Primary"
file = "default/localhost.zone"

[[zones]]
zone = "0.0.127.in-addr.arpa"
zone_type = "Primary"
file = "default/127.0.0.1.zone"
"#,
        bind_addr,
        port,
        zone_configs
    );

    let config_path = format!("{}/named.toml", config_dir);
    if let Err(e) = std::fs::write(&config_path, config_content) {
        warn!("failed write config {}: {}", config_path, e);
        return HttpResponse::InternalServerError().body("failed to write config");
    }

    // Copy default zone files if they exist
    let default_zones = ["localhost.zone", "127.0.0.1.zone"];
    for dz in default_zones.iter() {
        let src = format!("/home/outis/work-github/OutisCloud-hickory-dns/tests/test-data/test_configs/default/{}", dz);
        let dst = format!("{}/default/{}", config_dir, dz);
        if std::path::Path::new(&src).exists() {
            let _ = std::fs::create_dir_all(format!("{}/default", config_dir));
            let _ = std::fs::copy(&src, &dst);
        }
    }

    let bin = std::env::var("HICKORY_DNS_BIN").unwrap_or_else(|_| "./target/debug/hickory-dns".to_string());
    let mut cmd = Command::new(bin);
    cmd.arg("-d").arg(format!("-c={}", config_path));

    match cmd.spawn() {
        Ok(child) => {
            let mut procs = data.processes.lock().await;
            procs.insert(server_id.clone(), child);
            HttpResponse::Ok().json(serde_json::json!({"status":"started","server_id": server_id, "bind": format!("{}:{}", bind_addr, port)}))
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

async fn dns_status(data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    if let Some(tok) = auth_from_header(&req, &data.inner.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
        }
    } else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }

    let procs = data.processes.lock().await;
    let mut servers: Vec<serde_json::Value> = Vec::new();
    
    for (id, _) in procs.iter() {
        servers.push(serde_json::json!({
            "id": id,
            "status": "running"
        }));
    }
    
    HttpResponse::Ok().json(serde_json::json!({
        "servers": servers,
        "total": servers.len()
    }))
}

#[derive(Deserialize)]
struct ReloadDnsReq {
    id: String,
}

async fn dns_reload(body: web::Json<ReloadDnsReq>, data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    if let Some(tok) = auth_from_header(&req, &data.inner.jwt_secret) {
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "admin role required"}));
        }
    } else {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }

    let server_id = body.id.clone();
    let mut procs = data.processes.lock().await;
    
    if let Some(mut child) = procs.get_mut(&server_id) {
        match child.kill() {
            Ok(_) => {
                drop(procs);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                let mut new_procs = data.processes.lock().await;
                new_procs.remove(&server_id);
                HttpResponse::Ok().json(serde_json::json!({"status": "reloaded", "server_id": server_id}))
            }
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to reload: {}", e)}))
        }
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "server not found"}))
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

async fn delete_georule(path: web::Path<String>, data: web::Data<FullState>, req: HttpRequest) -> impl Responder {
    if auth_from_header(&req, &data.inner.jwt_secret).is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    let rule_id = path.into_inner();
    match (&*data.inner.db).execute("DELETE FROM georules WHERE id = $1", &[&rule_id]).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"success": true})),
        Err(e) => {
            warn!("delete_georule error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to delete rule"}))
        }
    }
}

#[derive(Deserialize)]
struct CreateZoneReq {
    domain: String,
}

async fn list_zones(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let auth = auth_from_header(&req, &data.jwt_secret);
    if auth.is_none() {
        return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
    }
    let tok = auth.unwrap();
    
    let rows = if tok.claims.role == "admin" {
        (&*data.db).query(
            "SELECT id::text, domain, COALESCE(owner::text, '') as owner, zone_type, created_at::text FROM zones ORDER BY domain",
            &[]
        ).await.unwrap_or_default()
    } else {
        let owner_str = tok.claims.sub.clone();
        (&*data.db).query(
            "SELECT id::text, domain, COALESCE(owner::text, '') as owner, zone_type, created_at::text FROM zones WHERE owner::text = $1 ORDER BY domain",
            &[&owner_str]
        ).await.unwrap_or_default()
    };
    
    let zones: Vec<ZoneWithOwner> = rows.into_iter().map(|r| ZoneWithOwner {
        id: r.get(0),
        domain: r.get(1),
        owner: r.get(2),
        zone_type: r.get(3),
        created_at: r.get(4),
    }).collect();
    
    HttpResponse::Ok().json(ApiResponse { success: true, data: Some(zones), error: None })
}

async fn create_zone(body: web::Json<CreateZoneReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let auth = auth_from_header(&req, &data.jwt_secret);
    if auth.is_none() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    let tok = auth.unwrap();
    
    // Validate domain
    if let Err(e) = validate_domain(&body.domain) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
    }
    
    let owner = tok.claims.sub.clone();
    let id = Uuid::new_v4();
    let id_str = id.to_string();
    let owner_str = owner.clone();
    let domain = body.domain.clone();
    
    match (&*data.db).execute(
        "INSERT INTO zones (id, domain, owner) VALUES ($1, $2, $3)",
        &[&id_str, &domain, &owner_str]
    ).await {
        Ok(_) => {
            info!("Created zone: {} for owner: {}", body.domain, owner);
            // Log to audit
            let details = serde_json::json!({"domain": &body.domain}).to_string();
            let _ = (&*data.db).execute(
                "INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5, $6)",
                &[&Uuid::new_v4().to_string(), &owner, &"create", &"zone", &id.to_string(), &details]
            ).await;
            HttpResponse::Created().json(serde_json::json!({"id": id.to_string(), "domain": &body.domain}))
        }
        Err(e) => {
            if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                warn!("create_zone error: domain already exists");
                HttpResponse::Conflict().json(serde_json::json!({"error": "domain already exists"}))
            } else {
                warn!("create_zone error: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("failed to create zone: {}", e)}))
            }
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
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
        }
        let tok = auth.unwrap();
        
        // Validate inputs
        if body.name.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "record name is required"}));
        }
        if let Err(e) = validate_record_type(&body.record_type) {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": e}));
        }
        if body.value.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "record value is required"}));
        }
        
        // Check zone ownership
        let zone_id_str = zone_id.to_string();
        let owner_check = (&*data.db).query_opt(
            "SELECT owner FROM zones WHERE id::text = $1",
            &[&zone_id_str]
        ).await;
        
        let zone_owner: Option<String> = match owner_check {
            Ok(Some(row)) => row.get(0),
            _ => None
        };
        
        // Allow if user is admin or zone owner
        if tok.claims.role != "admin" && zone_owner.as_ref() != Some(&tok.claims.sub) {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "access denied"}));
        }
    
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let ttl: i32 = body.ttl as i32;
    
        match (&*data.db).execute(
            "INSERT INTO records (id, zone_id, name, type, value, ttl) VALUES ($1, $2, $3, $4, $5, $6)",
            &[&id_str, &zone_id_str, &body.name, &body.record_type, &body.value, &ttl]
        ).await {
            Ok(_) => {
                info!("Created record: {} in zone: {}", body.name, zone_id_str);
                HttpResponse::Created().json(serde_json::json!({"id": id.to_string()}))
            }
            Err(e) => {
                warn!("create_record error: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({"error": "failed to create record"}))
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
            id: r.get(0),
            zone_id: r.get(1),
            name: r.get(2),
            record_type: r.get(3),
            value: r.get(4),
            ttl: r.get::<_, i32>(5) as u32,
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
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
        }
    
        let (zone_id, record_id) = path.into_inner();
    
        // Check zone ownership
        let owner_check = (&*data.db).query_opt(
            "SELECT owner FROM zones WHERE id::text = $1",
            &[&zone_id]
        ).await;
        
        let tok = auth.unwrap();
        let zone_owner: Option<String> = match owner_check {
            Ok(Some(row)) => row.get(0),
            _ => None
        };
        
        if tok.claims.role != "admin" && zone_owner.as_ref() != Some(&tok.claims.sub) {
            return HttpResponse::Forbidden().json(ErrorResponse { error: "access denied".to_string(), details: None });
        }
    
        match (&*data.db).execute(
            "DELETE FROM records WHERE id::text = $1 AND zone_id::text = $2",
            &[&record_id, &zone_id]
        ).await {
            Ok(count) => {
                if count == 0 {
                    HttpResponse::NotFound().json(ErrorResponse { error: "record not found".to_string(), details: None })
                } else {
                    info!("Deleted record: {} from zone: {}", record_id, zone_id);
                    HttpResponse::Ok().json(ApiResponse { success: true, data: Some(()), error: None })
                }
            }
            Err(e) => {
                warn!("delete_record error: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to delete record".to_string(), details: None })
            }
        }
    }

    // Audit logs endpoint
    #[derive(ToSchema, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AuditLogEntry {
        id: String,
        user_id: Option<String>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
        details: String,
        ip_address: Option<String>,
        created_at: String,
    }

    async fn list_audit_logs(
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
        }
        let tok = auth.unwrap();
        
        // Only admins can view audit logs
        if tok.claims.role != "admin" {
            return HttpResponse::Forbidden().json(ErrorResponse { error: "admin access required".to_string(), details: None });
        }
        
        let rows = (&*data.db).query(
            "SELECT id::text, COALESCE(user_id::text, '') as user_id, action, resource_type, 
                    COALESCE(resource_id, '') as resource_id, 
                    COALESCE(details::text, '') as details,
                    COALESCE(ip_address, '') as ip_address,
                    created_at::text 
             FROM audit_logs 
             ORDER BY created_at DESC 
             LIMIT 100",
            &[]
        ).await.unwrap_or_default();
        
        let logs: Vec<AuditLogEntry> = rows.into_iter().map(|r| AuditLogEntry {
            id: r.get(0),
            user_id: Some(r.get(1)).filter(|s: &String| !s.is_empty()),
            action: r.get(2),
            resource_type: r.get(3),
            resource_id: Some(r.get(4)).filter(|s: &String| !s.is_empty()),
            details: r.get(5),
            ip_address: Some(r.get(6)).filter(|s: &String| !s.is_empty()),
            created_at: r.get(7),
        }).collect();
        
        HttpResponse::Ok().json(ApiResponse { success: true, data: Some(logs), error: None })
    }

    // Get zone by ID
    async fn get_zone(
        path: web::Path<String>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
        }
        
        let zone_id = path.into_inner();
        
        match (&*data.db).query_one(
            "SELECT id::text, domain, COALESCE(owner::text, '') as owner, zone_type, created_at::text FROM zones WHERE id::text = $1",
            &[&zone_id]
        ).await {
            Ok(row) => {
                let zone = ZoneWithOwner {
                    id: row.get(0),
                    domain: row.get(1),
                    owner: row.get(2),
                    zone_type: row.get(3),
                    created_at: row.get(4),
                };
                HttpResponse::Ok().json(ApiResponse { success: true, data: Some(zone), error: None })
            }
            Err(_) => HttpResponse::NotFound().json(ErrorResponse { error: "zone not found".to_string(), details: None })
        }
    }

    // Export zone
    async fn export_zone(
        path: web::Path<String>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
        }
        
        let zone_id = path.into_inner();
        
        let zone_row = match (&*data.db).query_opt(
            "SELECT domain FROM zones WHERE id::text = $1",
            &[&zone_id]
        ).await {
            Ok(Some(row)) => row,
            _ => return HttpResponse::NotFound().json(ErrorResponse { error: "zone not found".to_string(), details: None })
        };
        
        let domain: String = zone_row.get(0);
        
        let records = (&*data.db).query(
            "SELECT name, type, value, ttl FROM records WHERE zone_id::text = $1",
            &[&zone_id]
        ).await.unwrap_or_default();
        
        let mut zone_content = format!("$ORIGIN {}\n$TTL 3600\n\n", domain);
        zone_content.push_str(&format!("@ 3600 IN SOA ns.{} hostmaster.{} 1 3600 3600 604800 3600\n\n", domain, domain));
        
        for r in records {
            let name: String = r.get(0);
            let typ: String = r.get(1);
            let value: String = r.get(2);
            let ttl: i32 = r.get(3);
            zone_content.push_str(&format!("{} {} IN {} {}\n", if name.is_empty() || name == "@" { "@" } else { &name }, ttl, typ, value));
        }
        
        HttpResponse::Ok()
            .content_type("text/plain")
            .body(zone_content)
    }

    #[derive(Deserialize)]
    struct ImportZoneReq {
        records: Vec<ImportRecordReq>,
    }

    #[derive(Deserialize)]
    struct ImportRecordReq {
        name: String,
        record_type: String,
        value: String,
        ttl: Option<u32>,
    }

    // Import zone
    async fn import_zone(
        path: web::Path<String>,
        body: web::Json<ImportZoneReq>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
        }
        
        let zone_id = path.into_inner();
        
        let mut imported = 0;
        for record in body.records.iter() {
            let ttl = record.ttl.unwrap_or(3600) as i32;
            match (&*data.db).execute(
                "INSERT INTO records (id, zone_id, name, type, value, ttl) VALUES ($1, $2, $3, $4, $5, $6)",
                &[&Uuid::new_v4().to_string(), &zone_id, &record.name, &record.record_type, &record.value, &ttl]
            ).await {
                Ok(_) => imported += 1,
                Err(e) => warn!("failed to import record: {}", e)
            }
        }
        
        HttpResponse::Ok().json(serde_json::json!({
            "imported": imported,
            "zone_id": zone_id
        }))
    }

    // Delete zone
    async fn delete_zone(
        path: web::Path<String>,
        data: web::Data<AppState>,
        req: HttpRequest,
    ) -> impl Responder {
        let auth = auth_from_header(&req, &data.jwt_secret);
        if auth.is_none() {
            return HttpResponse::Unauthorized().json(ErrorResponse { error: "unauthorized".to_string(), details: None });
        }
        let tok = auth.unwrap();
        
        let zone_id = path.into_inner();
        
        // Check ownership
        let owner_check = (&*data.db).query_opt(
            "SELECT owner FROM zones WHERE id::text = $1",
            &[&zone_id]
        ).await;
        
        let zone_owner: Option<String> = match owner_check {
            Ok(Some(row)) => row.get(0),
            _ => None
        };
        
        if tok.claims.role != "admin" && zone_owner.as_ref() != Some(&tok.claims.sub) {
            return HttpResponse::Forbidden().json(ErrorResponse { error: "access denied".to_string(), details: None });
        }
        
        match (&*data.db).execute("DELETE FROM zones WHERE id::text = $1", &[&zone_id]).await {
            Ok(count) => {
                if count == 0 {
                    HttpResponse::NotFound().json(ErrorResponse { error: "zone not found".to_string(), details: None })
                } else {
                    info!("Deleted zone: {}", zone_id);
                    HttpResponse::Ok().json(ApiResponse { success: true, data: Some(()), error: None })
                }
            }
            Err(e) => {
                warn!("delete_zone error: {}", e);
                HttpResponse::InternalServerError().json(ErrorResponse { error: "failed to delete zone".to_string(), details: None })
            }
        }
    }
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    info!("Starting control API...");

    // Required environment variables for production
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL environment variable must be set");
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET environment variable must be set");
    
    // Validate JWT_SECRET is sufficiently long for security
    if jwt_secret.len() < 32 {
        panic!("JWT_SECRET must be at least 32 characters for production security");
    }

    // CORS origins - can be comma-separated list or use ALLOWED_ORIGINS env var
    let allowed_origins = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173".to_string());
    let cors_origins: Vec<&str> = allowed_origins.split(',').map(|s| s.trim()).collect();

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
    
    // Build CORS with allowed origins from environment
    let cors_origins = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:3000,http://localhost:5173".to_string());

    HttpServer::new(move || {
        // Build CORS inside closure (can't be cloned)
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .max_age(3600);
        
        for origin in cors_origins.split(',') {
            let o = origin.trim();
            if !o.is_empty() {
                cors = cors.allowed_origin(o);
            }
        }
        
        App::new()
                .wrap(cors)
                .wrap(prometheus.clone())
                .app_data(app_data.clone())
                .app_data(full_data.clone())
            .route("/health", web::get().to(health))
            .route("/ready", web::get().to(ready))
            // Auth
            .route("/api/v1/auth/login", web::post().to(login))
            .route("/api/v1/auth/logout", web::post().to(logout))
            .route("/api/v1/auth/me", web::get().to(get_current_user))
            // Users
            .route("/api/v1/users", web::get().to(list_users))
            .route("/api/v1/users", web::post().to(create_user))
            .route("/api/v1/users/{id}", web::get().to(get_user))
            .route("/api/v1/users/{id}", web::put().to(update_user))
            .route("/api/v1/users/{id}", web::delete().to(delete_user))
            // Servers
            .route("/api/v1/servers", web::get().to(list_servers))
            .route("/api/v1/servers", web::post().to(create_server))
            .route("/api/v1/servers/{id}", web::delete().to(delete_server))
            // Zones
            .route("/api/v1/zones", web::get().to(list_zones))
            .route("/api/v1/zones", web::post().to(create_zone))
            .route("/api/v1/zones/{id}", web::get().to(get_zone))
            .route("/api/v1/zones/{id}", web::delete().to(delete_zone))
            .route("/api/v1/zones/{id}/export", web::get().to(export_zone))
            .route("/api/v1/zones/{id}/import", web::post().to(import_zone))
            // Records
            .route("/api/v1/zones/{id}/records", web::post().to(create_record))
            .route("/api/v1/zones/{id}/records", web::get().to(list_records))
            .route("/api/v1/zones/{zone_id}/records/{record_id}", web::put().to(update_record))
            .route("/api/v1/zones/{zone_id}/records/{record_id}", web::delete().to(delete_record))
            // Agents
            .route("/api/v1/agents/register", web::post().to(agent_register))
            .route("/api/v1/agents/heartbeat", web::post().to(agent_heartbeat))
            .route("/api/v1/agents", web::get().to(list_agents))
            .route("/api/v1/agents/{id}/config", web::get().to(agent_get_config))
            .route("/api/v1/agents/{id}/token/rotate", web::post().to(rotate_agent_token))
            // DNS Control
            .route("/api/v1/dns/start", web::post().to(start_dns_server))
            .route("/api/v1/dns/stop", web::post().to(stop_dns_server))
            .route("/api/v1/dns/status", web::get().to(dns_status))
            .route("/api/v1/dns/reload", web::post().to(dns_reload))
            // GeoRules
            .route("/api/v1/georules", web::post().to(create_georule))
            .route("/api/v1/georules", web::get().to(list_georules))
            .route("/api/v1/georules/{id}", web::delete().to(delete_georule))
            .route("/api/v1/georules/resolve", web::post().to(resolve_by_geo))
            // Config Push
            .route("/api/v1/config/push", web::post().to(push_config_to_agents))
            // Audit Logs
            .route("/api/v1/audit/logs", web::get().to(list_audit_logs))
            // Metrics
            .route("/metrics", web::get().to(|| async move {
                let encoder = TextEncoder::new();
                let metric_families = gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap_or(());
                HttpResponse::Ok().content_type("text/plain; version=0.0.4").body(buffer)
            }))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
