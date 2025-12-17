-- Add MFA backup codes table
CREATE TABLE tbl_mfa_backup_code (
    id BIGSERIAL PRIMARY KEY,
    mfa_id BIGINT NOT NULL REFERENCES tbl_mfa(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT false,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mfa_backup_code_mfa ON tbl_mfa_backup_code(mfa_id);
CREATE INDEX idx_mfa_backup_code_used ON tbl_mfa_backup_code(used);

-- Add MFA recovery questions
CREATE TABLE tbl_mfa_recovery_question (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    answer_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mfa_recovery_question_user ON tbl_mfa_recovery_question(user_id);

-- Add password history for security
CREATE TABLE tbl_password_history (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES tbl_user(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    changed_by VARCHAR(255)
);

CREATE INDEX idx_password_history_user ON tbl_password_history(user_id);
CREATE INDEX idx_password_history_changed ON tbl_password_history(changed_at);

-- Function to prevent password reuse
CREATE OR REPLACE FUNCTION check_password_reuse(user_id BIGINT, new_password_hash TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    reuse_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO reuse_count
    FROM tbl_password_history
    WHERE user_id = $1 AND password_hash = $2
    AND changed_at > CURRENT_TIMESTAMP - INTERVAL '365 days';
    
    RETURN reuse_count = 0;
END;
$$ LANGUAGE plpgsql;