package com.auth.config;

import com.auth.constants.ApiPaths;
import com.auth.exception.AccessDeniedExceptionHandler;
import com.auth.exception.AuthenticationExceptionHandler;
import com.auth.security.JwtAuthenticationFilter;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;
import java.util.Arrays;

/**
 * @author Roeurt Kesei
 * Security configuration for the application.
 */
@Configuration
@EnableConfigurationProperties({
    AppProperties.Api.class,
    AppProperties.Database.class,
    AppProperties.PasswordReset.class,
    AppProperties.R2dbc.class
})
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ReactiveUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final ApiPaths apiPaths;
    private final AuthenticationExceptionHandler authenticationEntryPoint;
    private final AccessDeniedExceptionHandler accessDeniedHandler;

    public SecurityConfig(
        JwtAuthenticationFilter jwtAuthenticationFilter,
        ReactiveUserDetailsService userDetailsService,
        PasswordEncoder passwordEncoder,
        ApiPaths apiPaths,
        AuthenticationExceptionHandler authenticationEntryPoint,
        AccessDeniedExceptionHandler accessDeniedHandler
    ) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.apiPaths = apiPaths;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Bean
    public ReactiveAuthenticationManager authenticationManager() {
        UserDetailsRepositoryReactiveAuthenticationManager manager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        manager.setPasswordEncoder(passwordEncoder);
        return manager;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        ReactiveAuthenticationManager jwtAuthManager = auth -> Mono.just(auth);
        AuthenticationWebFilter authWebFilter = new AuthenticationWebFilter(jwtAuthManager);
        authWebFilter.setServerAuthenticationConverter(jwtAuthenticationFilter);
        authWebFilter.setAuthenticationFailureHandler(
            new ServerAuthenticationEntryPointFailureHandler(authenticationEntryPoint)
        );

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(e -> e.authenticationEntryPoint(authenticationEntryPoint).accessDeniedHandler(accessDeniedHandler))
                .authorizeExchange(exchanges -> {
                    permitPublicRoutes(exchanges);
                    authorizeProtectedRoutes(exchanges);
                    exchanges.anyExchange().authenticated();
                })
                .addFilterAt(authWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .build();
    }

    private void permitPublicRoutes(ServerHttpSecurity.AuthorizeExchangeSpec exchanges) {
        exchanges.pathMatchers(apiPaths.auth()).permitAll();
        exchanges.pathMatchers(
            ApiPaths.SWAGGER_HTML,
            ApiPaths.SWAGGER_UI,
            ApiPaths.API_DOCS,
            ApiPaths.API_DOCS_BASE
        ).permitAll();
    }

    private void authorizeProtectedRoutes(ServerHttpSecurity.AuthorizeExchangeSpec exchanges) {
        authorizeAuthenticated(exchanges, apiPaths.users());
        authorizeAuthenticated(exchanges, apiPaths.roles());
        authorizeAuthenticated(exchanges, apiPaths.permissions());
    }

    private void authorizeAuthenticated(ServerHttpSecurity.AuthorizeExchangeSpec exchanges, String pattern) {
        exchanges.pathMatchers(HttpMethod.GET, pattern).authenticated();
        exchanges.pathMatchers(HttpMethod.POST, pattern).authenticated();
        exchanges.pathMatchers(HttpMethod.PUT, pattern).authenticated();
        exchanges.pathMatchers(HttpMethod.DELETE, pattern).authenticated();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}