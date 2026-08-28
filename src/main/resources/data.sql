-- Insert permissions
INSERT INTO tbl_permission (name, description) VALUES 
('USER_READ', 'Read user information'),
('USER_WRITE', 'Create and update users'),
('USER_DELETE', 'Delete users'),
('ROLE_READ', 'Read role information'),
('ROLE_WRITE', 'Create and update roles'),
('ROLE_DELETE', 'Delete roles'),
('PERMISSION_READ', 'Read permission information'),
('PERMISSION_WRITE', 'Create and update permissions'),
('PERMISSION_DELETE', 'Delete permissions')
ON CONFLICT (name) DO NOTHING;

-- Insert roles
INSERT INTO tbl_role (name, description) VALUES 
('ADMIN', 'Administrator with full access'),
('USER', 'Regular user with basic access')
ON CONFLICT (name) DO NOTHING;

-- Create default admin user (password: admin123)
INSERT INTO tbl_user (first_name, last_name, username, password, email, status, is_deleted) VALUES 
('System', 'Administrator', 'admin', '$2a$12$v3ZTNqnTf.DW6iI0P1fD1eW3rliM9yXSDczQ7oKFWxfoNXjtI.XtS', 'admin@example.com', '1001', false)
ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password;

-- Set published_id and modified_id for admin user
UPDATE tbl_user 
SET published_id = (SELECT id FROM tbl_user WHERE username = 'admin'),
    modified_id = (SELECT id FROM tbl_user WHERE username = 'admin')
WHERE username = 'admin' AND (published_id IS NULL OR modified_id IS NULL);

-- Set published_id and modified_id for all permissions (admin created them)
UPDATE tbl_permission 
SET published_id = (SELECT id FROM tbl_user WHERE username = 'admin'),
    modified_id = (SELECT id FROM tbl_user WHERE username = 'admin')
WHERE published_id IS NULL OR modified_id IS NULL;

-- Set published_id and modified_id for all roles (admin created them)
UPDATE tbl_role 
SET published_id = (SELECT id FROM tbl_user WHERE username = 'admin'),
    modified_id = (SELECT id FROM tbl_user WHERE username = 'admin')
WHERE published_id IS NULL OR modified_id IS NULL;

-- Assign permissions to ADMIN role
INSERT INTO tbl_role_permission (role_id, permission_id)
SELECT r.id, p.id 
FROM tbl_role r, tbl_permission p 
WHERE r.name = 'ADMIN' 
ON CONFLICT DO NOTHING;

-- Assign permissions to USER role
INSERT INTO tbl_role_permission (role_id, permission_id)
SELECT r.id, p.id 
FROM tbl_role r, tbl_permission p 
WHERE r.name = 'USER' AND p.name IN ('USER_READ')
ON CONFLICT DO NOTHING;

-- Assign ADMIN role to admin user
INSERT INTO tbl_user_role (user_id, role_id)
SELECT u.id, r.id 
FROM tbl_user u, tbl_role r 
WHERE u.username = 'admin' AND r.name = 'ADMIN'
ON CONFLICT DO NOTHING;