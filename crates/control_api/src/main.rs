use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, http::header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use actix_web_prom::PrometheusMetrics;
use log::{info, warn};
use sqlx::PgPool;
use uuid::Uuid;
use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, encode, decode, TokenData};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, PasswordVerifier, PasswordHash}};
use rand_core::OsRng;

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
    db: PgPool,
    jwt_secret: String,
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status":"ok"}))
}

async fn migrate_db(pool: &PgPool) -> Result<(), sqlx::Error> {
    // run embedded migrations if present (placeholder)
    // We'll run simple CREATE TABLE IF NOT EXISTS statements to keep migrations lightweight here
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL);")
        .execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS servers (id UUID PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, region TEXT);")
        .execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS zones (id UUID PRIMARY KEY, domain TEXT NOT NULL, owner UUID);")
        .execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS records (id UUID PRIMARY KEY, zone_id UUID REFERENCES zones(id) ON DELETE CASCADE, name TEXT, type TEXT, value TEXT, ttl INT);")
        .execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS agents (id UUID PRIMARY KEY, name TEXT, addr TEXT, last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT now());")
        .execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS georules (id UUID PRIMARY KEY, zone_id UUID REFERENCES zones(id) ON DELETE CASCADE, match_type TEXT, match_value TEXT, target TEXT);")
        .execute(pool).await?;
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
    let pool = &data.db;
    if let Ok(rec) = sqlx::query("SELECT id, password_hash, role FROM users WHERE username = $1")
        .bind(&body.username)
        .map(|row: sqlx::postgres::PgRow| (row.get::<Uuid, _>(0), row.get::<String, _>(1), row.get::<Option<String>, _>(2)))
        .fetch_one(pool).await {
        let (id, password_hash, role) = rec;
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
    let pool = &data.db;
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(req.password.as_bytes(), &salt).unwrap().to_string();
    let id = Uuid::new_v4();
    let role = "user";
    let res = sqlx::query("INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(&req.username)
        .bind(&password_hash)
        .bind(role)
        .execute(pool).await;
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
    let pool = &data.db;
    let rows = sqlx::query("SELECT id, name, address, region FROM servers")
        .map(|row: sqlx::postgres::PgRow| (row.get::<Uuid, _>(0), row.get::<String, _>(1), row.get::<String, _>(2), row.get::<Option<String>, _>(3)))
        .fetch_all(pool).await.unwrap_or_default();
    let servers: Vec<ServerInfo> = rows.into_iter().map(|r| ServerInfo { id: r.0.to_string(), name: r.1, address: r.2, region: r.3 }).collect();
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
    let pool = &data.db;
    let id = Uuid::new_v4();
    let res = sqlx::query("INSERT INTO servers (id, name, address, region) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(&body.name)
        .bind(&body.address)
        .bind(&body.region)
        .execute(pool).await;
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

async fn agent_register(body: web::Json<AgentRegistration>, data: web::Data<AppState>) -> impl Responder {
    let pool = &data.db;
    let id = Uuid::new_v4();
    let res = sqlx::query("INSERT INTO agents (id, name, addr) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&body.name)
        .bind(&body.addr)
        .execute(pool).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => {
            warn!("agent_register error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn agent_heartbeat(body: web::Json<AgentRegistration>, data: web::Data<AppState>) -> impl Responder {
    let pool = &data.db;
    let res = sqlx::query("UPDATE agents SET last_heartbeat = now() WHERE addr = $1")
        .bind(&body.addr)
        .execute(pool).await;
    match res {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return HttpResponse::NotFound().finish();
            }
            HttpResponse::Ok().finish()
        }
        Err(e) => { warn!("agent_heartbeat error: {}", e); HttpResponse::InternalServerError().finish() }
    }
}

#[derive(Deserialize)]
struct CreateZoneReq {
    domain: String,
}

async fn list_zones(data: web::Data<AppState>, _req: HttpRequest) -> impl Responder {
    let pool = &data.db;
    let rows = sqlx::query("SELECT id, domain FROM zones")
        .map(|row: sqlx::postgres::PgRow| (row.get::<Uuid, _>(0), row.get::<String, _>(1)))
        .fetch_all(pool).await.unwrap_or_default();
    let zones: Vec<Zone> = rows.into_iter().map(|r| Zone { id: r.0.to_string(), domain: r.1, records: vec![] }).collect();
    HttpResponse::Ok().json(zones)
}

async fn create_zone(body: web::Json<CreateZoneReq>, data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    if auth_from_header(&req, &data.jwt_secret).is_none() {
        return HttpResponse::Unauthorized().finish();
    }
    let pool = &data.db;
    let id = Uuid::new_v4();
    let res = sqlx::query("INSERT INTO zones (id, domain) VALUES ($1, $2)")
        .bind(id)
        .bind(&body.domain)
        .execute(pool).await;
    match res {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"id": id.to_string()})),
        Err(e) => {
            warn!("create_zone error: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

// Placeholder: function to push configuration to agents (secure HTTPS/gRPC in production)
async fn push_config_to_agent(_agent_id: &str) {
    // TODO: implement secure config push
}

// Placeholder GeoDNS control endpoints
async fn list_georules(_data: web::Data<AppState>, _req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!([]))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    info!("Starting control API...");

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:password@db:5432/hickory".to_string());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "replace_with_a_super_secret".to_string());

    let pool = PgPool::connect(&database_url).await.expect("cannot connect to db");
    migrate_db(&pool).await.expect("db migrate failed");

    let app_state = AppState { db: pool.clone(), jwt_secret: jwt_secret.clone() };

    // Basic Prometheus metrics via actix-web-prom
    let prometheus = PrometheusMetrics::new("control_api", Some("/metrics"), None);

    HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            .app_data(web::Data::new(app_state.clone()))
            .route("/api/v1/auth/login", web::post().to(login))
            .route("/api/v1/users", web::post().to(create_user))
            .route("/api/v1/servers", web::get().to(list_servers))
            .route("/api/v1/servers", web::post().to(create_server))
                    .route("/api/v1/zones", web::get().to(list_zones))
                    .route("/api/v1/zones", web::post().to(create_zone))
            .route("/api/v1/agents/register", web::post().to(agent_register))
                    .route("/api/v1/agents/heartbeat", web::post().to(agent_heartbeat))
            .route("/api/v1/georules", web::get().to(list_georules))
            .route("/health", web::get().to(health))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
