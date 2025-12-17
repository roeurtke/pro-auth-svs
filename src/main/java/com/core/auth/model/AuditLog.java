package com.core.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
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
    
    private String userId;
    private String action;
    private String resourceType;
    private String resourceId;
    private String oldValue;
    private String newValue;
    private String ipAddress;
    private String userAgent;
    
    private LocalDateTime timestamp;
    
    @Builder.Default
    private boolean success = true;
    private String errorMessage;
}