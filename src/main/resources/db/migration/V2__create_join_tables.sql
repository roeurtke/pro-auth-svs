-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_username ON tbl_user(username);
CREATE INDEX IF NOT EXISTS idx_user_email ON tbl_user(email);
CREATE INDEX IF NOT EXISTS idx_user_enabled ON tbl_user(enabled);
CREATE INDEX IF NOT EXISTS idx_user_locked ON tbl_user(locked);

CREATE INDEX IF NOT EXISTS idx_role_code ON tbl_role(code);
CREATE INDEX IF NOT EXISTS idx_role_system ON tbl_role(system_role);

CREATE INDEX IF NOT EXISTS idx_permission_code ON tbl_permission(code);
CREATE INDEX IF NOT EXISTS idx_permission_category ON tbl_permission(category);

CREATE INDEX IF NOT EXISTS idx_user_role_user ON tbl_user_role(user_id);
CREATE INDEX IF NOT EXISTS idx_user_role_role ON tbl_user_role(role_id);
CREATE INDEX IF NOT EXISTS idx_user_role_composite ON tbl_user_role(user_id, role_id);

CREATE INDEX IF NOT EXISTS idx_role_permission_role ON tbl_role_permission(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permission_permission ON tbl_role_permission(permission_id);
CREATE INDEX IF NOT EXISTS idx_role_permission_composite ON tbl_role_permission(role_id, permission_id);

CREATE INDEX IF NOT EXISTS idx_token_token ON tbl_token(token);
CREATE INDEX IF NOT EXISTS idx_token_user ON tbl_token(user_id);
CREATE INDEX IF NOT EXISTS idx_token_type ON tbl_token(token_type);
CREATE INDEX IF NOT EXISTS idx_token_expires ON tbl_token(expires_at);
CREATE INDEX IF NOT EXISTS idx_token_revoked ON tbl_token(revoked);

CREATE INDEX IF NOT EXISTS idx_session_token ON tbl_session(session_token);
CREATE INDEX IF NOT EXISTS idx_session_user ON tbl_session(user_id);
CREATE INDEX IF NOT EXISTS idx_session_active ON tbl_session(active);
CREATE INDEX IF NOT EXISTS idx_session_expires ON tbl_session(expires_at);

CREATE INDEX IF NOT EXISTS idx_mfa_user ON tbl_mfa(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_enabled ON tbl_mfa(enabled);

CREATE INDEX IF NOT EXISTS idx_audit_user ON tbl_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON tbl_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON tbl_audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON tbl_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_success ON tbl_audit_log(success);

CREATE INDEX IF NOT EXISTS idx_api_client_client_id ON tbl_api_client(client_id);
CREATE INDEX IF NOT EXISTS idx_api_client_active ON tbl_api_client(active);
CREATE INDEX IF NOT EXISTS idx_api_client_expires ON tbl_api_client(expires_at);

-- Add unique constraints
ALTER TABLE tbl_user_role ADD CONSTRAINT unique_user_role UNIQUE (user_id, role_id);
ALTER TABLE tbl_role_permission ADD CONSTRAINT unique_role_permission UNIQUE (role_id, permission_id);