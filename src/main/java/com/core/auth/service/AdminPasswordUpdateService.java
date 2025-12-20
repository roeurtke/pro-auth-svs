package com.core.auth.service;

import com.core.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminPasswordUpdateService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TransactionalOperator txOperator;

    @Bean
    public CommandLineRunner updateAdminPassword() {
        return args -> {
            log.info("Checking admin user password...");

            Mono<Void> updateMono = userRepository.findByUsername("admin")
                    .flatMap(user -> {
                        String placeholder = "$2a$10$X8zWqU6bK9K6J7V6J5Y5Y.Mq5Z5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5Y5";
                        if (user.getPassword().equals(placeholder)) {
                            log.info("Updating admin user password...");
                            user.setPassword(passwordEncoder.encode("Admin@123"));
                            return txOperator.execute(status -> userRepository.save(user))
                                    .then(); // Convert Mono<User> -> Mono<Void>
                        }
                        log.info("Admin password is already hashed");
                        return Mono.empty(); // No update needed
                    });

            updateMono.subscribe(
                    unused -> log.info("Admin password check complete"),
                    error -> log.error("Error updating admin password", error)
            );
        };
    }
}