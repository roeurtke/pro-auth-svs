package com.core.auth.service;

import com.core.auth.model.User;
import com.core.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements ReactiveUserDetailsService {
    
    private final UserRepository userRepository;
    private final RoleService roleService;
    
    @Override
    public Mono<UserDetails> findByUsername(String username) {
        log.debug("Looking up user by username: {}", username);
        
        return userRepository.findByUsername(username)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("User not found with username: {}", username);
                    return Mono.error(new UsernameNotFoundException("User not found: " + username));
                }))
                .doOnNext(user -> log.debug("Found user: {} with id: {}", user.getUsername(), user.getId()))
                .flatMap(user -> 
                    // Get authorities synchronously since getAuthoritiesForUser returns Set<GrantedAuthority>
                    Mono.fromCallable(() -> roleService.getAuthoritiesForUser(user.getId()))
                        .onErrorResume(e -> {
                            log.warn("Failed to get authorities for user {}: {}", user.getUsername(), e.getMessage());
                            return Mono.just(new HashSet<>());
                        })
                        .map(authorities -> convertToUserDetails(user, authorities))
                )
                .doOnError(error -> log.error("Error finding user by username: {}", error.getMessage()));
    }
    
    private UserDetails convertToUserDetails(User user, Set<GrantedAuthority> authorities) {
        // Validate critical fields
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        
        String username = user.getUsername();
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("User username cannot be null or empty. User ID: " + user.getId());
        }
        
        String password = user.getPassword();
        if (password == null) {
            log.warn("User {} has null password, using empty string", username);
            password = "";
        }
        
        log.debug("Creating UserDetails for {} with {} authorities", username, authorities.size());
        
        return org.springframework.security.core.userdetails.User.builder()
                .username(username)
                .password(password)
                .authorities(authorities)
                .disabled(!user.isEnabled())
                .accountExpired(!user.isAccountNonExpired())
                .accountLocked(!user.isAccountNonLocked())
                .credentialsExpired(!user.isCredentialsNonExpired())
                .build();
    }
}