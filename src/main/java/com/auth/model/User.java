package com.auth.model;

import com.auth.util.EnumStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import java.util.stream.Collectors;

/**
 * @author Roeurt Kesei
 * User entity representing a user in the authentication system.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_user")
public class User implements UserDetails, CredentialsContainer {

    @Id
    private Long id;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private String phoneNumber;
    private String email;
    @Builder.Default
    private String status = EnumStatus.ACTIVATED.getValue();
    @Builder.Default
    private Boolean isDeleted = false;
    private LocalDateTime publishedAt;
    private LocalDateTime modifiedAt;
    private LocalDateTime lastActiveAt;
    private Long publishedId;
    private Long modifiedId;

    @Transient
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @Transient
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();

    public User(String firstName, String lastName, String username, String password, String email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.username = username;
        this.password = password;
        this.email = email;
        this.status = EnumStatus.ACTIVATED.getValue();
        this.isDeleted = false;
        this.publishedAt = LocalDateTime.now();
        this.modifiedAt = LocalDateTime.now();
    }

    public String getStatus() { return status; }

    // VALIDATED setter
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

    // Convenience method (NOT persisted)
    @Transient
    public String getStatusName() {
        return EnumStatus.fromValue(this.status).getDisplayName();
    }

    /**
     * Returns the authorities granted to the user
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
            .flatMap(role -> Stream.concat(
                Stream.of(new SimpleGrantedAuthority("ROLE_" + role.getName())),
                role.getAuthorities().stream()
            ))
            .collect(Collectors.toUnmodifiableSet());
    }

    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }

    @Override
    public void eraseCredentials() {
        this.password = null;
    }
}
