package com.core.auth.service;

import com.core.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminPasswordUpdateService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Bean
    public CommandLineRunner updateAdminPassword() {
        return args -> {
            log.info("Checking admin user password...");
            
            userRepository.findByUsername("admin")
                .flatMap(user -> {
                    // Check if password needs to be updated (if it's the placeholder)
                    if (user.getPassword().equals("$2a$10$X8zWqU6bK9K6J7V6J5Y5Y.Mq5Z5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5")) {
                        log.info("Updating admin user password...");
                        user.setPassword(passwordEncoder.encode("Admin@123"));
                        return userRepository.save(user)
                            .doOnSuccess(updated -> log.info("✅ Admin password updated successfully"));
                    }
                    log.info("Admin password is already hashed");
                    return reactor.core.publisher.Mono.just(user);
                })
                .subscribe();
        };
    }
}