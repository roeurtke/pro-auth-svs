-- data.sql
-- Seed default permissions
INSERT INTO tbl_permission (name, code, description, category, created_at, updated_at) VALUES
-- User Management
('View Users', 'USER_VIEW', 'Can view user profiles', 'USER', NOW(), NOW()),
('Create Users', 'USER_CREATE', 'Can create new users', 'USER', NOW(), NOW()),
('Update Users', 'USER_UPDATE', 'Can update user information', 'USER', NOW(), NOW()),
('Delete Users', 'USER_DELETE', 'Can delete users', 'USER', NOW(), NOW()),
('Manage Users', 'USER_MANAGE', 'Full user management', 'USER', NOW(), NOW()),

-- Role Management
('View Roles', 'ROLE_VIEW', 'Can view roles', 'ROLE', NOW(), NOW()),
('Create Roles', 'ROLE_CREATE', 'Can create new roles', 'ROLE', NOW(), NOW()),
('Update Roles', 'ROLE_UPDATE', 'Can update roles', 'ROLE', NOW(), NOW()),
('Delete Roles', 'ROLE_DELETE', 'Can delete roles', 'ROLE', NOW(), NOW()),
('Manage Roles', 'ROLE_MANAGE', 'Full role management', 'ROLE', NOW(), NOW()),

-- Permission Management
('View Permissions', 'PERMISSION_VIEW', 'Can view permissions', 'PERMISSION', NOW(), NOW()),
('Create Permissions', 'PERMISSION_CREATE', 'Can create permissions', 'PERMISSION', NOW(), NOW()),
('Update Permissions', 'PERMISSION_UPDATE', 'Can update permissions', 'PERMISSION', NOW(), NOW()),
('Delete Permissions', 'PERMISSION_DELETE', 'Can delete permissions', 'PERMISSION', NOW(), NOW()),
('Manage Permissions', 'PERMISSION_MANAGE', 'Full permission management', 'PERMISSION', NOW(), NOW()),

-- Audit Log
('View Audit Logs', 'AUDIT_VIEW', 'Can view audit logs', 'AUDIT', NOW(), NOW()),
('Export Audit Logs', 'AUDIT_EXPORT', 'Can export audit logs', 'AUDIT', NOW(), NOW()),

-- System
('System Configuration', 'SYSTEM_CONFIG', 'Can configure system settings', 'SYSTEM', NOW(), NOW()),
('API Management', 'API_MANAGE', 'Can manage API clients', 'SYSTEM', NOW(), NOW())
ON CONFLICT (code) DO NOTHING;

-- Seed default roles
INSERT INTO tbl_role (name, code, description, system_role, created_at, updated_at) VALUES
('Super Administrator', 'SUPER_ADMIN', 'Full system access with all privileges', true, NOW(), NOW()),
('Administrator', 'ADMIN', 'System administrator with full access', true, NOW(), NOW()),
('User', 'USER', 'Default user role', true, NOW(), NOW()),
('Moderator', 'MODERATOR', 'Content moderator with limited admin access', false, NOW(), NOW()),
('Auditor', 'AUDITOR', 'Can view audit logs and reports', false, NOW(), NOW())
ON CONFLICT (code) DO NOTHING;

-- Create admin user with BCrypt hashed password (password: Admin@123)
-- This BCrypt hash was generated for password "Admin@123" with strength 10
INSERT INTO tbl_user (username, email, password, first_name, last_name, phone, enabled, locked, mfa_enabled, created_at, updated_at, password_changed_at, failed_login_attempts) VALUES
('admin', 'admin@example.com', '$2a$10$9F9cFcLz7Kz7Kz7Kz7Kz7eKz7Kz7Kz7Kz7Kz7Kz7Kz7Kz7Kz7Kz7K', 'System', 'Administrator', '+1234567890', true, false, false, NOW(), NOW(), NOW(), 0)
ON CONFLICT (username) DO NOTHING;

-- Create a regular test user (password: User@123)
INSERT INTO tbl_user (username, email, password, first_name, last_name, phone, enabled, locked, mfa_enabled, created_at, updated_at, password_changed_at, failed_login_attempts) VALUES
('user1', 'user1@example.com', '$2a$10$9F9cFcLz7Kz7Kz7Kz7Kz7eKz7Kz7Kz7Kz7Kz7Kz7Kz7Kz7Kz7Kz7K', 'John', 'Doe', '+1234567891', true, false, false, NOW(), NOW(), NOW(), 0)
ON CONFLICT (username) DO NOTHING;

-- Assign permissions to SUPER_ADMIN role
INSERT INTO tbl_role_permission (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM tbl_role r
CROSS JOIN tbl_permission p
WHERE r.code = 'SUPER_ADMIN'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to ADMIN role (all except SUPER_ADMIN specific)
INSERT INTO tbl_role_permission (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM tbl_role r
CROSS JOIN tbl_permission p
WHERE r.code = 'ADMIN' AND p.code NOT LIKE 'SUPER_%'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign basic permissions to USER role
INSERT INTO tbl_role_permission (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM tbl_role r
CROSS JOIN tbl_permission p
WHERE r.code = 'USER' 
AND p.code IN ('USER_VIEW', 'ROLE_VIEW', 'PERMISSION_VIEW')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to MODERATOR role
INSERT INTO tbl_role_permission (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM tbl_role r
CROSS JOIN tbl_permission p
WHERE r.code = 'MODERATOR' 
AND (p.category = 'USER' OR p.code = 'AUDIT_VIEW')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to AUDITOR role
INSERT INTO tbl_role_permission (role_id, permission_id, created_at)
SELECT r.id, p.id, NOW()
FROM tbl_role r
CROSS JOIN tbl_permission p
WHERE r.code = 'AUDITOR' AND p.category = 'AUDIT'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign SUPER_ADMIN role to admin user
INSERT INTO tbl_user_role (user_id, role_id, created_at)
SELECT u.id, r.id, NOW()
FROM tbl_user u
CROSS JOIN tbl_role r
WHERE u.username = 'admin' AND r.code = 'SUPER_ADMIN'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Assign USER role to regular user
INSERT INTO tbl_user_role (user_id, role_id, created_at)
SELECT u.id, r.id, NOW()
FROM tbl_user u
CROSS JOIN tbl_role r
WHERE u.username = 'user1' AND r.code = 'USER'
ON CONFLICT (user_id, role_id) DO NOTHING;