package com.core.auth.config;

// import com.core.auth.security.JwtAuthManager;
import com.core.auth.repository.JwtSecurityContextRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableConfigurationProperties({
    AppProperties.Argon2.class,
    AppProperties.Mfa.class,
    AppProperties.Database.class,
    AppProperties.R2dbc.class
})
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

//     private final JwtAuthManager jwtAuthManager;
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
                        // Admin endpoints
                        .pathMatchers(HttpMethod.GET, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.POST, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PUT, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.DELETE, apiConfig.getAdminPath() + "/**").hasRole("ADMIN")
                        // Authenticated endpoints
                        .pathMatchers(apiConfig.getAuthPath() + "/logout").authenticated()
                        .pathMatchers(apiConfig.getAuthPath() + "/mfa/**").authenticated()
                        .anyExchange().authenticated()
                )
                .securityContextRepository(securityContextRepository)
                // REMOVE THIS LINE - Don't set global authentication manager
                // .authenticationManager(jwtAuthManager)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(corsConfig.getAllowedOrigins() != null ? corsConfig.getAllowedOrigins() :
                Arrays.asList("http://localhost:3000", "http://localhost:8080"));
        configuration.setAllowedMethods(corsConfig.getAllowedMethods() != null ? corsConfig.getAllowedMethods() :
                Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(corsConfig.getAllowedHeaders() != null ? corsConfig.getAllowedHeaders() :
                Arrays.asList("*"));
        configuration.setAllowCredentials(corsConfig.isAllowCredentials());
        configuration.setMaxAge(corsConfig.getMaxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Single bean for all password encoding
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}