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
        return userRepository.findByUsername(username)
                .switchIfEmpty(Mono.error(new UsernameNotFoundException("User not found: " + username)))
                .flatMap(user -> 
                    roleService.getUserWithAuthorities(user.getId())
                        .map(this::convertToUserDetails)
                );
    }
    
    private UserDetails convertToUserDetails(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add role authorities
        if (user.getRoles() != null) {
            user.getRoles().forEach(role -> 
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getCode()))
            );
        }
        
        // Add permission authorities
        if (user.getPermissions() != null) {
            user.getPermissions().forEach(permission -> 
                authorities.add(new SimpleGrantedAuthority("PERM_" + permission.getCode()))
            );
        }
        
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(authorities)
                .disabled(!user.isEnabled())
                .accountExpired(!user.isAccountNonExpired())
                .accountLocked(!user.isAccountNonLocked())
                .credentialsExpired(!user.isCredentialsNonExpired())
                .build();
    }
}