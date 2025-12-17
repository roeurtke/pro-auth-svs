package com.core.auth.config;

import com.core.auth.security.JwtAuthManager;
import com.core.auth.repository.JwtSecurityContextRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableConfigurationProperties({Argon2Properties.class, MfaProperties.class})
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthManager jwtAuthManager;
    private final JwtSecurityContextRepository securityContextRepository;
    private final ApiConfig apiConfig;
    private final CorsConfig corsConfig;
    
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeExchange(exchanges -> exchanges
                        // Public endpoints
                        .pathMatchers(HttpMethod.POST, 
                            apiConfig.getAuthPath() + "/login",
                            apiConfig.getAuthPath() + "/register",
                            apiConfig.getAuthPath() + "/refresh",
                            apiConfig.getAuthPath() + "/password/reset/request",
                            apiConfig.getAuthPath() + "/password/reset/confirm"
                        ).permitAll()
                        .pathMatchers(HttpMethod.GET, 
                            "/swagger-ui/**",
                            "/v3/api-docs/**",
                            "/webjars/**",
                            "/actuator/health"
                        ).permitAll()
                        
                        // Role-based endpoints
                        .pathMatchers(HttpMethod.GET, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.POST, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PUT, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.DELETE, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        
                        // User management requires appropriate permissions
                        .pathMatchers(HttpMethod.GET, apiConfig.getUserPath() + "/**").authenticated()
                        .pathMatchers(HttpMethod.PUT, apiConfig.getUserPath() + "/**").authenticated()
                        .pathMatchers(HttpMethod.DELETE, apiConfig.getUserPath() + "/**").hasAuthority("PERM_USER_DELETE")
                        
                        // Role management requires admin role and specific permissions
                        .pathMatchers(HttpMethod.POST, apiConfig.getRolePath() + "/**")
                            .access((monoAuth, authzCtx) -> monoAuth.map(authentication -> {
                                boolean hasRole = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                                boolean hasPerm = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("PERM_ROLE_MANAGE"));
                                return new AuthorizationDecision(hasRole && hasPerm);
                            }))
                        .pathMatchers(HttpMethod.PUT, apiConfig.getRolePath() + "/**")
                            .access((monoAuth, authzCtx) -> monoAuth.map(authentication -> {
                                boolean hasRole = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                                boolean hasPerm = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("PERM_ROLE_MANAGE"));
                                return new AuthorizationDecision(hasRole && hasPerm);
                            }))
                        .pathMatchers(HttpMethod.DELETE, apiConfig.getRolePath() + "/**")
                            .access((monoAuth, authzCtx) -> monoAuth.map(authentication -> {
                                boolean hasRole = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                                boolean hasPerm = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("PERM_ROLE_MANAGE"));
                                return new AuthorizationDecision(hasRole && hasPerm);
                            }))
                        
                        // Permission management requires specific permissions
                        .pathMatchers(HttpMethod.POST, apiConfig.getPermissionPath() + "/**")
                            .access((monoAuth, authzCtx) -> monoAuth.map(authentication -> {
                                boolean hasRole = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                                boolean hasPerm = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("PERM_PERMISSION_MANAGE"));
                                return new AuthorizationDecision(hasRole && hasPerm);
                            }))
                        .pathMatchers(HttpMethod.PUT, apiConfig.getPermissionPath() + "/**")
                            .access((monoAuth, authzCtx) -> monoAuth.map(authentication -> {
                                boolean hasRole = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                                boolean hasPerm = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("PERM_PERMISSION_MANAGE"));
                                return new AuthorizationDecision(hasRole && hasPerm);
                            }))
                        .pathMatchers(HttpMethod.DELETE, apiConfig.getPermissionPath() + "/**")
                            .access((monoAuth, authzCtx) -> monoAuth.map(authentication -> {
                                boolean hasRole = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN") || a.getAuthority().equals("ROLE_SUPER_ADMIN"));
                                boolean hasPerm = authentication.getAuthorities().stream()
                                        .anyMatch(a -> a.getAuthority().equals("PERM_PERMISSION_MANAGE"));
                                return new AuthorizationDecision(hasRole && hasPerm);
                            }))
                        
                        // Authenticated endpoints
                        .pathMatchers(apiConfig.getAuthPath() + "/logout").authenticated()
                        .pathMatchers(apiConfig.getAuthPath() + "/mfa/**").authenticated()
                        
                        .anyExchange().authenticated()
                )
                .securityContextRepository(securityContextRepository)
                .authenticationManager(jwtAuthManager)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Set allowed origins
        if (corsConfig.getAllowedOrigins() != null && !corsConfig.getAllowedOrigins().isEmpty()) {
            configuration.setAllowedOrigins(corsConfig.getAllowedOrigins());
        } else {
            // Default to localhost for development
            configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:8080"));
        }
        
        // Set allowed methods
        if (corsConfig.getAllowedMethods() != null && !corsConfig.getAllowedMethods().isEmpty()) {
            configuration.setAllowedMethods(corsConfig.getAllowedMethods());
        } else {
            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        }
        
        // Set allowed headers
        if (corsConfig.getAllowedHeaders() != null && !corsConfig.getAllowedHeaders().isEmpty()) {
            configuration.setAllowedHeaders(corsConfig.getAllowedHeaders());
        } else {
            configuration.setAllowedHeaders(Arrays.asList("*"));
        }
        
        // Set allow credentials
        configuration.setAllowCredentials(corsConfig.isAllowCredentials());
        
        // Set max age
        configuration.setMaxAge(corsConfig.getMaxAge());
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }
}