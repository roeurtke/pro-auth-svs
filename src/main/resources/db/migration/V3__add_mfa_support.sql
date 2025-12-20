-- Add foreign keys after tables are populated
ALTER TABLE tbl_user_role 
ADD CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES tbl_user(id) ON DELETE CASCADE;

ALTER TABLE tbl_user_role 
ADD CONSTRAINT fk_user_role_role FOREIGN KEY (role_id) REFERENCES tbl_role(id) ON DELETE CASCADE;

ALTER TABLE tbl_role_permission 
ADD CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES tbl_role(id) ON DELETE CASCADE;

ALTER TABLE tbl_role_permission 
ADD CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES tbl_permission(id) ON DELETE CASCADE;