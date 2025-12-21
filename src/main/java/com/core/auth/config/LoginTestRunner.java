package com.core.auth.config;

import com.core.auth.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LoginTestRunner implements CommandLineRunner {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Test credentials
        String username = "admin";
        String rawPassword = "Admin@123";

        userDetailsService.findByUsername(username)
                .subscribe(userDetails -> {
                    boolean matches = passwordEncoder.matches(rawPassword, userDetails.getPassword());
                    System.out.println("Password matches for " + username + ": " + matches);
                    System.out.println("Authorities: " + userDetails.getAuthorities());
                }, error -> {
                    System.err.println("Error: " + error.getMessage());
                });
    }
}
