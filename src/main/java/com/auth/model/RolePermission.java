package com.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.relational.core.mapping.Table;

/**
 * @author Roeurt Kesei
 * RolePermission entity representing the association between roles and permissions.
 */
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_role_permission")
public class RolePermission {
    
    private Long roleId;
    private Long permissionId;

}