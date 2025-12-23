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
@Table("tbl_session")
public class Session {
    
    @Id
    private Long id;
    
    @Column("user_id")
    private Long userId;  // Change from String to Long
    
    @Column("session_token")
    private String sessionToken;
    
    @Column("ip_address")
    private String ipAddress;
    
    @Column("user_agent")
    private String userAgent;
    
    @Column("device_info")
    private String deviceInfo;
    
    private String location;
    
    @Column("login_at")
    private LocalDateTime loginAt;
    
    @Column("last_activity_at")
    private LocalDateTime lastActivityAt;
    
    @Column("logout_at")
    private LocalDateTime logoutAt;
    
    @Column("expires_at")
    private LocalDateTime expiresAt;
    
    private boolean active;
    
    @Column("logout_reason")
    private String logoutReason;
    
    public boolean isValid() {
        return active && expiresAt.isAfter(LocalDateTime.now());
    }
}