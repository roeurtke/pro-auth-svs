-- Additional indexes for join tables
CREATE INDEX idx_user_role_created ON tbl_user_role(created_at);
CREATE INDEX idx_role_permission_created ON tbl_role_permission(created_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for automatic updated_at
CREATE TRIGGER update_user_updated_at BEFORE UPDATE ON tbl_user
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_role_updated_at BEFORE UPDATE ON tbl_role
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permission_updated_at BEFORE UPDATE ON tbl_permission
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- View for user roles and permissions
CREATE VIEW vw_user_roles_permissions AS
SELECT 
    u.id as user_id,
    u.username,
    u.email,
    r.id as role_id,
    r.code as role_code,
    r.name as role_name,
    p.id as permission_id,
    p.code as permission_code,
    p.name as permission_name,
    p.category as permission_category
FROM tbl_user u
LEFT JOIN tbl_user_role ur ON u.id = ur.user_id
LEFT JOIN tbl_role r ON ur.role_id = r.id
LEFT JOIN tbl_role_permission rp ON r.id = rp.role_id
LEFT JOIN tbl_permission p ON rp.permission_id = p.id
WHERE u.enabled = true AND u.locked = false;

-- Function to check if user has permission
CREATE OR REPLACE FUNCTION has_permission(user_id BIGINT, permission_code TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    has_perm BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 
        FROM vw_user_roles_permissions 
        WHERE user_id = $1 AND permission_code = $2
    ) INTO has_perm;
    
    RETURN has_perm;
END;
$$ LANGUAGE plpgsql;