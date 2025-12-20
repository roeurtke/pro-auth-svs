-- Drop existing tables if they exist
DROP TABLE IF EXISTS tbl_role_permission;
DROP TABLE IF EXISTS tbl_user_role;
DROP TABLE IF EXISTS tbl_permission;
DROP TABLE IF EXISTS tbl_role;
DROP TABLE IF EXISTS tbl_audit_log;
DROP TABLE IF EXISTS tbl_session;
DROP TABLE IF EXISTS tbl_token;
DROP TABLE IF EXISTS tbl_mfa;
DROP TABLE IF EXISTS tbl_api_client;
DROP TABLE IF EXISTS tbl_user;

-- Create tables
CREATE TABLE tbl_user (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    phone VARCHAR(20),
    enabled BOOLEAN DEFAULT true,
    locked BOOLEAN DEFAULT false,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    password_changed_at TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0
);

CREATE TABLE tbl_role (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    code VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    system_role BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tbl_permission (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tbl_user_role (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, role_id)
);

CREATE TABLE tbl_role_permission (
    id BIGSERIAL PRIMARY KEY,
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

CREATE TABLE tbl_token (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    token VARCHAR(512) UNIQUE NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    revoked BOOLEAN DEFAULT false,
    expired BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);

CREATE TABLE tbl_session (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    session_token VARCHAR(512) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info VARCHAR(255),
    location VARCHAR(100),
    login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    active BOOLEAN DEFAULT true,
    logout_reason VARCHAR(100)
);

CREATE TABLE tbl_mfa (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    secret VARCHAR(255) NOT NULL,
    backup_codes TEXT,
    method VARCHAR(20) DEFAULT 'TOTP',
    enabled BOOLEAN DEFAULT false,
    enabled_at TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE TABLE tbl_audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    old_value TEXT,
    new_value TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT true,
    error_message TEXT
);

CREATE TABLE tbl_api_client (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(100) UNIQUE NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    scopes TEXT,
    redirect_uris TEXT,
    grant_types TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    active BOOLEAN DEFAULT true,
    confidential BOOLEAN DEFAULT true
);

-- Create indexes for performance
CREATE INDEX idx_user_username ON tbl_user(username);
CREATE INDEX idx_user_email ON tbl_user(email);
CREATE INDEX idx_user_enabled ON tbl_user(enabled);
CREATE INDEX idx_user_locked ON tbl_user(locked);

CREATE INDEX idx_role_code ON tbl_role(code);
CREATE INDEX idx_role_system ON tbl_role(system_role);

CREATE INDEX idx_permission_code ON tbl_permission(code);
CREATE INDEX idx_permission_category ON tbl_permission(category);

CREATE INDEX idx_user_role_user ON tbl_user_role(user_id);
CREATE INDEX idx_user_role_role ON tbl_user_role(role_id);
CREATE INDEX idx_user_role_composite ON tbl_user_role(user_id, role_id);

CREATE INDEX idx_role_permission_role ON tbl_role_permission(role_id);
CREATE INDEX idx_role_permission_permission ON tbl_role_permission(permission_id);
CREATE INDEX idx_role_permission_composite ON tbl_role_permission(role_id, permission_id);

CREATE INDEX idx_token_token ON tbl_token(token);
CREATE INDEX idx_token_user ON tbl_token(user_id);
CREATE INDEX idx_token_type ON tbl_token(token_type);
CREATE INDEX idx_token_expires ON tbl_token(expires_at);
CREATE INDEX idx_token_revoked ON tbl_token(revoked);

CREATE INDEX idx_session_token ON tbl_session(session_token);
CREATE INDEX idx_session_user ON tbl_session(user_id);
CREATE INDEX idx_session_active ON tbl_session(active);
CREATE INDEX idx_session_expires ON tbl_session(expires_at);

CREATE INDEX idx_mfa_user ON tbl_mfa(user_id);
CREATE INDEX idx_mfa_enabled ON tbl_mfa(enabled);

CREATE INDEX idx_audit_user ON tbl_audit_log(user_id);
CREATE INDEX idx_audit_action ON tbl_audit_log(action);
CREATE INDEX idx_audit_resource ON tbl_audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_timestamp ON tbl_audit_log(timestamp);
CREATE INDEX idx_audit_success ON tbl_audit_log(success);

CREATE INDEX idx_api_client_client_id ON tbl_api_client(client_id);
CREATE INDEX idx_api_client_active ON tbl_api_client(active);
CREATE INDEX idx_api_client_expires ON tbl_api_client(expires_at);