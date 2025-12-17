package com.core.auth.config;

import io.r2dbc.spi.ConnectionFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.r2dbc.repository.config.EnableR2dbcRepositories;
import org.springframework.r2dbc.connection.init.CompositeDatabasePopulator;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Configuration
@EnableR2dbcRepositories(basePackages = "com.auth.repository")
@RequiredArgsConstructor
@EnableScheduling
public class DatabaseConfig {
    
    private final com.core.auth.repository.RoleRepository roleRepository;
    private final com.core.auth.repository.PermissionRepository permissionRepository;
    private final com.core.auth.repository.RolePermissionRepository rolePermissionRepository;
    private final com.core.auth.repository.UserRepository userRepository;
    private final com.core.auth.repository.UserRoleRepository userRoleRepository;
    private final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    
    /**
     * Initialize database schema and run migrations
     */
    @Bean
    public ConnectionFactoryInitializer initializer(ConnectionFactory connectionFactory) {
        ConnectionFactoryInitializer initializer = new ConnectionFactoryInitializer();
        initializer.setConnectionFactory(connectionFactory);
        
        CompositeDatabasePopulator populator = new CompositeDatabasePopulator();
        
        // Execute SQL files in order
        populator.addPopulators(
            new ResourceDatabasePopulator(new ClassPathResource("db/migration/V1__initial_schema.sql")),
            new ResourceDatabasePopulator(new ClassPathResource("db/migration/V2__create_join_tables.sql")),
            new ResourceDatabasePopulator(new ClassPathResource("db/migration/V3__add_mfa_support.sql"))
        );
        
        initializer.setDatabasePopulator(populator);
        return initializer;
    }
    
    /**
     * Seed initial data after application starts
     */
    @Bean
    public CommandLineRunner seedData() {
        return args -> {
            seedPermissions()
                .then(seedRoles())
                .then(seedAdminUser())
                .then(assignPermissionsToRoles())
                .subscribe(
                    result -> log.info("Database seeding completed successfully"),
                    error -> log.error("Database seeding failed: {}", error.getMessage())
                );
        };
    }
    
    /**
     * Seed default permissions
     */
    @Transactional
    public reactor.core.publisher.Mono<Void> seedPermissions() {
        log.info("Seeding permissions...");
        
        return permissionRepository.deleteAll()
            .thenMany(reactor.core.publisher.Flux.just(
                // User Management Permissions
                com.core.auth.model.Permission.builder()
                    .name("View Users")
                    .code("USER_VIEW")
                    .description("Can view user profiles")
                    .category("USER")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Create Users")
                    .code("USER_CREATE")
                    .description("Can create new users")
                    .category("USER")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Update Users")
                    .code("USER_UPDATE")
                    .description("Can update user information")
                    .category("USER")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Delete Users")
                    .code("USER_DELETE")
                    .description("Can delete users")
                    .category("USER")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Manage Users")
                    .code("USER_MANAGE")
                    .description("Full user management")
                    .category("USER")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                // Role Management Permissions
                com.core.auth.model.Permission.builder()
                    .name("View Roles")
                    .code("ROLE_VIEW")
                    .description("Can view roles")
                    .category("ROLE")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Create Roles")
                    .code("ROLE_CREATE")
                    .description("Can create new roles")
                    .category("ROLE")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Update Roles")
                    .code("ROLE_UPDATE")
                    .description("Can update roles")
                    .category("ROLE")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Delete Roles")
                    .code("ROLE_DELETE")
                    .description("Can delete roles")
                    .category("ROLE")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Manage Roles")
                    .code("ROLE_MANAGE")
                    .description("Full role management")
                    .category("ROLE")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                // Permission Management Permissions
                com.core.auth.model.Permission.builder()
                    .name("View Permissions")
                    .code("PERMISSION_VIEW")
                    .description("Can view permissions")
                    .category("PERMISSION")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Create Permissions")
                    .code("PERMISSION_CREATE")
                    .description("Can create permissions")
                    .category("PERMISSION")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Update Permissions")
                    .code("PERMISSION_UPDATE")
                    .description("Can update permissions")
                    .category("PERMISSION")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Delete Permissions")
                    .code("PERMISSION_DELETE")
                    .description("Can delete permissions")
                    .category("PERMISSION")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Manage Permissions")
                    .code("PERMISSION_MANAGE")
                    .description("Full permission management")
                    .category("PERMISSION")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                // Audit Log Permissions
                com.core.auth.model.Permission.builder()
                    .name("View Audit Logs")
                    .code("AUDIT_VIEW")
                    .description("Can view audit logs")
                    .category("AUDIT")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("Export Audit Logs")
                    .code("AUDIT_EXPORT")
                    .description("Can export audit logs")
                    .category("AUDIT")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                // System Permissions
                com.core.auth.model.Permission.builder()
                    .name("System Configuration")
                    .code("SYSTEM_CONFIG")
                    .description("Can configure system settings")
                    .category("SYSTEM")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Permission.builder()
                    .name("API Management")
                    .code("API_MANAGE")
                    .description("Can manage API clients")
                    .category("SYSTEM")
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build()
            ))
            .flatMap(permissionRepository::save)
            .then()
            .doOnSuccess(v -> log.info("Permissions seeded successfully"));
    }
    
    /**
     * Seed default roles
     */
    @Transactional
    public reactor.core.publisher.Mono<Void> seedRoles() {
        log.info("Seeding roles...");
        
        return roleRepository.deleteAll()
            .thenMany(reactor.core.publisher.Flux.just(
                com.core.auth.model.Role.builder()
                    .name("Super Administrator")
                    .code("SUPER_ADMIN")
                    .description("Full system access with all privileges")
                    .systemRole(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Role.builder()
                    .name("Administrator")
                    .code("ADMIN")
                    .description("System administrator with full access")
                    .systemRole(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Role.builder()
                    .name("User")
                    .code("USER")
                    .description("Default user role")
                    .systemRole(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Role.builder()
                    .name("Moderator")
                    .code("MODERATOR")
                    .description("Content moderator with limited admin access")
                    .systemRole(false)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build(),
                
                com.core.auth.model.Role.builder()
                    .name("Auditor")
                    .code("AUDITOR")
                    .description("Can view audit logs and reports")
                    .systemRole(false)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build()
            ))
            .flatMap(roleRepository::save)
            .then()
            .doOnSuccess(v -> log.info("Roles seeded successfully"));
    }
    
    /**
     * Create default admin user
     */
    @Transactional
    public reactor.core.publisher.Mono<Void> seedAdminUser() {
        log.info("Creating admin user...");
        
        return userRepository.findByUsername("admin")
            .switchIfEmpty(
                userRepository.save(
                    com.core.auth.model.User.builder()
                        .username("admin")
                        .email("admin@example.com")
                        .password(passwordEncoder.encode("Admin@123"))
                        .firstName("System")
                        .lastName("Administrator")
                        .phone("+1234567890")
                        .enabled(true)
                        .locked(false)
                        .mfaEnabled(false)
                        .createdAt(LocalDateTime.now())
                        .updatedAt(LocalDateTime.now())
                        .lastLoginAt(null)
                        .passwordChangedAt(LocalDateTime.now())
                        .failedLoginAttempts(0)
                        .build()
                )
                .doOnSuccess(user -> log.info("Admin user created with ID: {}", user.getId()))
            )
            .then();
    }
    
    /**
     * Assign permissions to roles
     */
    @Transactional
    public reactor.core.publisher.Mono<Void> assignPermissionsToRoles() {
        log.info("Assigning permissions to roles...");
        
        return rolePermissionRepository.deleteAll()
            .then(reactor.core.publisher.Mono.zip(
                roleRepository.findByCode("SUPER_ADMIN"),
                roleRepository.findByCode("ADMIN"),
                roleRepository.findByCode("USER"),
                roleRepository.findByCode("MODERATOR"),
                roleRepository.findByCode("AUDITOR"),
                permissionRepository.findAll().collectList()
            ))
            .flatMap(tuple -> {
                com.core.auth.model.Role superAdminRole = tuple.getT1();
                com.core.auth.model.Role adminRole = tuple.getT2();
                com.core.auth.model.Role userRole = tuple.getT3();
                com.core.auth.model.Role moderatorRole = tuple.getT4();
                com.core.auth.model.Role auditorRole = tuple.getT5();
                java.util.List<com.core.auth.model.Permission> allPermissions = tuple.getT6();
                
                java.util.List<com.core.auth.model.RolePermission> rolePermissions = new java.util.ArrayList<>();
                
                // SUPER_ADMIN gets all permissions
                allPermissions.forEach(permission -> 
                    rolePermissions.add(new com.core.auth.model.RolePermission(superAdminRole.getId(), permission.getId()))
                );
                
                // ADMIN gets all permissions except SUPER_ADMIN specific ones
                allPermissions.stream()
                    .filter(p -> !p.getCode().startsWith("SUPER_"))
                    .forEach(permission -> 
                        rolePermissions.add(new com.core.auth.model.RolePermission(adminRole.getId(), permission.getId()))
                    );
                
                // USER gets basic permissions
                allPermissions.stream()
                    .filter(p -> p.getCode().equals("USER_VIEW") || 
                                p.getCode().equals("ROLE_VIEW") || 
                                p.getCode().equals("PERMISSION_VIEW"))
                    .forEach(permission -> 
                        rolePermissions.add(new com.core.auth.model.RolePermission(userRole.getId(), permission.getId()))
                    );
                
                // MODERATOR gets user management permissions
                allPermissions.stream()
                    .filter(p -> p.getCategory().equals("USER") || p.getCode().equals("AUDIT_VIEW"))
                    .forEach(permission -> 
                        rolePermissions.add(new com.core.auth.model.RolePermission(moderatorRole.getId(), permission.getId()))
                    );
                
                // AUDITOR gets audit permissions
                allPermissions.stream()
                    .filter(p -> p.getCategory().equals("AUDIT"))
                    .forEach(permission -> 
                        rolePermissions.add(new com.core.auth.model.RolePermission(auditorRole.getId(), permission.getId()))
                    );
                
                return rolePermissionRepository.saveAll(rolePermissions)
                    .collectList()
                    .doOnSuccess(saved -> log.info("Assigned {} permissions to roles", saved.size()));
            })
            .then()
            .doOnSuccess(v -> {
                log.info("Assigning SUPER_ADMIN role to admin user...");
                assignSuperAdminRole();
            });
    }
    
    /**
     * Assign SUPER_ADMIN role to admin user
     */
    @Transactional
    public void assignSuperAdminRole() {
        userRepository.findByUsername("admin")
            .zipWith(roleRepository.findByCode("SUPER_ADMIN"))
            .flatMap(tuple -> {
                com.core.auth.model.User adminUser = tuple.getT1();
                com.core.auth.model.Role superAdminRole = tuple.getT2();
                
                return userRoleRepository.save(
                    new com.core.auth.model.UserRole(adminUser.getId(), superAdminRole.getId())
                );
            })
            .doOnSuccess(v -> log.info("SUPER_ADMIN role assigned to admin user"))
            .doOnError(e -> log.error("Failed to assign SUPER_ADMIN role: {}", e.getMessage()))
            .subscribe();
    }
    
    /**
     * Clean up expired tokens (runs daily)
     */
    @org.springframework.scheduling.annotation.Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired tokens...");
        
        // This would be implemented when TokenRepository is available
        // tokenRepository.deleteExpiredTokens(LocalDateTime.now()).subscribe();
    }
    
    /**
     * Clean up inactive sessions (runs hourly)
     */
    @org.springframework.scheduling.annotation.Scheduled(cron = "0 0 * * * ?") // Hourly
    @Transactional
    public void cleanupInactiveSessions() {
        log.info("Cleaning up inactive sessions...");
        
        // This would be implemented when SessionRepository is available
        // sessionRepository.deleteExpiredSessions(LocalDateTime.now()).subscribe();
    }
}