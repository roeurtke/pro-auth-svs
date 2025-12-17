package com.core.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_role")
public class Role {
    
    @Id
    private Long id;
    
    private String name;
    private String code;
    private String description;
    
    @CreatedDate
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    @Builder.Default
    private boolean systemRole = false;
    
    @Transient
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();
    
    @Transient
    @Builder.Default
    private Set<User> users = new HashSet<>();
}