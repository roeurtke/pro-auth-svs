package com.core.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_audit_log")
public class AuditLog {
    
    @Id
    private Long id;
    
    @Column("user_id")
    private Long userId;  // Changed from String to Long
    
    private String action;
    
    @Column("resource_type")
    private String resourceType;
    
    @Column("resource_id")
    private String resourceId;
    
    @Column("old_value")
    private String oldValue;
    
    @Column("new_value")
    private String newValue;
    
    @Column("ip_address")
    private String ipAddress;
    
    @Column("user_agent")
    private String userAgent;
    
    private LocalDateTime timestamp;
    
    @Builder.Default
    private boolean success = true;
    
    @Column("error_message")
    private String errorMessage;
}