package com.auth.model;

import com.auth.util.EnumStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

/**
 * @author Roeurt Kesei
 * Permission entity representing a permission in the authentication system.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_permission")
public class Permission {
    
    @Id
    private Long id;
    private String name;
    private String description;
    @Builder.Default
    private String status = EnumStatus.ACTIVATED.getValue();
    @Builder.Default
    private Boolean isDeleted = false;
    private LocalDateTime publishedAt;
    private LocalDateTime modifiedAt;
    private Long publishedId;
    private Long modifiedId;
    public Permission(String name, String description) {
        this.name = name;
        this.description = description;
        this.status = EnumStatus.ACTIVATED.getValue();
        this.isDeleted = false;
        this.publishedAt = LocalDateTime.now();
        this.modifiedAt = LocalDateTime.now();
    }

    public String getStatus() { return status; }

    public void setStatus(String status) {
        EnumStatus.fromValue(status);
        this.status = status;
    }

    public void applyStatus(String status) {
        setStatus(status);
        if (EnumStatus.ACTIVATED.getValue().equals(status)) {
            this.isDeleted = false;
        }
    }

    @Transient
    public String getStatusName() {
        return EnumStatus.fromValue(this.status).getDisplayName();
    }
    
}