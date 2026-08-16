package com.core.auth.service;

import com.core.auth.model.Permission;
import com.core.auth.model.Role;
import com.core.auth.repository.PermissionRepository;
import com.core.auth.repository.RolePermissionRepository;
import com.core.auth.repository.RoleRepository;
import com.core.auth.repository.UserRoleRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import reactor.core.publisher.Flux;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RoleServiceAuthorityTest {

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @Mock
    private RolePermissionRepository rolePermissionRepository;

    @Mock
    private AuditLogService auditLogService;

    @InjectMocks
    private RoleService roleService;

    @Test
    void getAuthoritiesForUserShouldReturnReactiveAuthorities() {
        Role role = Role.builder().code("ADMIN").build();
        Permission permission = Permission.builder().code("USER_VIEW").build();

        when(roleRepository.findByUserId(7L)).thenReturn(Flux.just(role));
        when(permissionRepository.findByUserId(7L)).thenReturn(Flux.just(permission));

        StepVerifier.create(roleService.getAuthoritiesForUser(7L))
                .assertNext(authorities -> {
                    assertThat(authorities)
                            .extracting(GrantedAuthority::getAuthority)
                            .containsExactlyInAnyOrder("ADMIN", "USER_VIEW");
                })
                .verifyComplete();
    }
}
