package com.core.auth.service;

import com.core.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminPasswordUpdateService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner updateAdminPassword() {
        return args -> {
            userRepository.findByUsername("admin")
                .flatMap(user -> {
                    if (!user.getPassword().startsWith("{bcrypt}")
                            && !user.getPassword().startsWith("{argon2}")) {

                        user.setPassword(passwordEncoder.encode("Admin@123"));
                        return userRepository.save(user);
                    }
                    return Mono.empty();
                })
                .subscribe();
        };
    }
}