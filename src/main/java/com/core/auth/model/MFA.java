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
@Table("tbl_mfa")
public class MFA {
    
    @Id
    private Long id;
    
    private String userId;
    private String secret;
    private String backupCodes;
    private String method; // TOTP, SMS, EMAIL
    
    private LocalDateTime enabledAt;
    private LocalDateTime lastUsedAt;
    
    @Builder.Default
    private boolean enabled = false;
    
    public String[] getBackupCodesArray() {
        return backupCodes != null ? backupCodes.split(",") : new String[0];
    }
}