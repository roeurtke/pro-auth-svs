package com.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.relational.core.mapping.Table;

/**
 * @author Roeurt Kesei
 * UserRole entity representing the association between users and roles.
 */
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_user_role")
public class UserRole {
    
    private Long userId;
    private Long roleId;

}