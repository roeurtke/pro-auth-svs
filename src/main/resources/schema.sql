-- Create tables
CREATE TABLE IF NOT EXISTS tbl_user (
    id BIGSERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone_number VARCHAR(20),
    email VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT '1001',
    is_deleted BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active_at TIMESTAMP,
    published_id BIGINT,
    modified_id BIGINT,
    CONSTRAINT fk_user_published_by FOREIGN KEY (published_id) REFERENCES tbl_user(id),
    CONSTRAINT fk_user_modified_by FOREIGN KEY (modified_id) REFERENCES tbl_user(id)
);

CREATE TABLE IF NOT EXISTS tbl_role (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255),
    status VARCHAR(50) DEFAULT '1001',
    is_deleted BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_id BIGINT,
    modified_id BIGINT,
    CONSTRAINT fk_role_published_by FOREIGN KEY (published_id) REFERENCES tbl_user(id),
    CONSTRAINT fk_role_modified_by FOREIGN KEY (modified_id) REFERENCES tbl_user(id)
);

CREATE TABLE IF NOT EXISTS tbl_permission (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255),
    status VARCHAR(50) DEFAULT '1001',
    is_deleted BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_id BIGINT,
    modified_id BIGINT,
    CONSTRAINT fk_permission_published_by FOREIGN KEY (published_id) REFERENCES tbl_user(id),
    CONSTRAINT fk_permission_modified_by FOREIGN KEY (modified_id) REFERENCES tbl_user(id)
);

CREATE TABLE IF NOT EXISTS tbl_user_role (
    user_id BIGINT REFERENCES tbl_user(id) ON DELETE CASCADE,
    role_id BIGINT REFERENCES tbl_role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS tbl_role_permission (
    role_id BIGINT REFERENCES tbl_role(id) ON DELETE CASCADE,
    permission_id BIGINT REFERENCES tbl_permission(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS tbl_user_activity (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES tbl_user(id) ON DELETE SET NULL,
    target_user_id BIGINT REFERENCES tbl_user(id) ON DELETE SET NULL,
    username VARCHAR(100),
    event_type VARCHAR(50) NOT NULL,
    request_method VARCHAR(10),
    request_path VARCHAR(500),
    ip_address VARCHAR(100),
    user_agent VARCHAR(500),
    successful BOOLEAN NOT NULL DEFAULT TRUE,
    details VARCHAR(1000),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_username ON tbl_user(username);
CREATE INDEX IF NOT EXISTS idx_user_email ON tbl_user(email);
CREATE INDEX IF NOT EXISTS idx_role_name ON tbl_role(name);
CREATE INDEX IF NOT EXISTS idx_permission_name ON tbl_permission(name);
CREATE INDEX IF NOT EXISTS idx_user_activity_user ON tbl_user_activity(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_activity_event ON tbl_user_activity(event_type, created_at DESC);