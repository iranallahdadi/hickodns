-- Migration 001: Initial schema
-- Creates all core tables for the DNS management system

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Servers table
CREATE TABLE IF NOT EXISTS servers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    region TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Zones table
CREATE TABLE IF NOT EXISTS zones (
    id UUID PRIMARY KEY,
    domain TEXT NOT NULL,
    owner UUID REFERENCES users(id) ON DELETE SET NULL,
    zone_type TEXT NOT NULL DEFAULT 'primary',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(domain)
);

CREATE INDEX IF NOT EXISTS idx_zones_owner ON zones(owner);
CREATE INDEX IF NOT EXISTS idx_zones_domain ON zones(domain);

-- Records table
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

CREATE INDEX IF NOT EXISTS idx_records_zone_id ON records(zone_id);
CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(name, type);

-- Agents table
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

CREATE INDEX IF NOT EXISTS idx_agents_enabled ON agents(enabled);

-- GeoRules table
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

CREATE INDEX IF NOT EXISTS idx_georules_zone_id ON georules(zone_id);

-- Audit logs table
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

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Agent configs table for release channels
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

CREATE INDEX IF NOT EXISTS idx_agent_configs_agent_id ON agent_configs(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_configs_active ON agent_configs(agent_id, is_active);

-- Insert default admin user (password: admin123)
-- This should be changed on first login
INSERT INTO users (id, username, password_hash, role) 
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin',
    '$argon2id$v=19$m=65536,t=3,p=1$N2FlZDkyOGI5MmEzMmNlZWMwYzUyYjY3ZjhiNTQxMGU$Bie8oWt96SKARq6DQqPBEJify2F8YJ6hMwwY15bUsAI',
    'admin'
) ON CONFLICT (username) DO NOTHING;
