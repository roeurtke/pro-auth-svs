// package com.core.auth.config;

// import com.core.auth.model.User;
// import com.core.auth.repository.UserRepository;
// import com.core.auth.service.CustomUserDetailsService;
// import lombok.RequiredArgsConstructor;
// import org.springframework.boot.CommandLineRunner;
// import org.springframework.security.authentication.ReactiveAuthenticationManager;
// // import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// // import org.springframework.security.core.Authentication;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Component;
// import reactor.core.publisher.Mono;

// import java.time.LocalDateTime;

// @Component
// @RequiredArgsConstructor
// public class AuthTestRunner implements CommandLineRunner {

//     private final UserRepository userRepository;
//     private final CustomUserDetailsService userDetailsService;
//     private final PasswordEncoder passwordEncoder;
    
//     @org.springframework.beans.factory.annotation.Qualifier("loginAuthenticationManager")
//     private final ReactiveAuthenticationManager loginAuthenticationManager;

//     @Override
//     public void run(String... args) throws Exception {
//         String username = "admin";
//         String email = "admin@example.com";
//         String rawPassword = "admin123";

//         System.out.println("======================================");
//         System.out.println("AUTHENTICATION SYSTEM TEST");
//         System.out.println("======================================");

//         // Step 1: Debug which AuthenticationManager is injected
//         System.out.println("1. Checking injected AuthenticationManager:");
//         System.out.println("   Bean class: " + loginAuthenticationManager.getClass().getName());
//         System.out.println("   Is JwtAuthManager? " + 
//             loginAuthenticationManager.getClass().getSimpleName().contains("JwtAuthManager"));

//         // Step 2: Test manual flow (bypass AuthenticationManager)
//         System.out.println("\n2. Testing manual authentication flow (bypassing AuthenticationManager):");
        
//         // Ensure user exists
//         User user = userRepository.findByUsername(username)
//                 .switchIfEmpty(Mono.defer(() -> {
//                     System.out.println("   Creating test user...");
//                     String encodedPassword = passwordEncoder.encode(rawPassword);
                    
//                     User newUser = User.builder()
//                             .username(username)
//                             .email(email)
//                             .password(encodedPassword)
//                             .firstName("Admin")
//                             .lastName("User")
//                             .enabled(true)
//                             .locked(false)
//                             .mfaEnabled(false)
//                             .failedLoginAttempts(0)
//                             .createdAt(LocalDateTime.now())
//                             .updatedAt(LocalDateTime.now())
//                             .build();
                    
//                     return userRepository.save(newUser);
//                 }))
//                 .flatMap(existingUser -> {
//                     if (existingUser.isLocked() || existingUser.getFailedLoginAttempts() > 0) {
//                         existingUser.setLocked(false);
//                         existingUser.setFailedLoginAttempts(0);
//                         existingUser.setUpdatedAt(LocalDateTime.now());
//                         return userRepository.save(existingUser);
//                     }
//                     return Mono.just(existingUser);
//                 })
//                 .block();

//         System.out.println("3. User status:");
//         System.out.println("   Username: " + user.getUsername());
//         System.out.println("   Enabled: " + user.isEnabled());
//         System.out.println("   Locked: " + user.isLocked());
        
//         // Test password directly
//         boolean passwordMatches = passwordEncoder.matches(rawPassword, user.getPassword());
//         System.out.println("   Password matches: " + passwordMatches);

//         // Test UserDetailsService
//         System.out.println("\n4. Testing UserDetailsService:");
//         var userDetails = userDetailsService.findByUsername(username)
//                 .doOnNext(details -> {
//                     System.out.println("   ✅ UserDetails found: " + details.getUsername());
//                     System.out.println("   Password in UserDetails: " + 
//                         (details.getPassword() != null ? "[HASHED]" : "NULL"));
//                 })
//                 .block();

//         if (userDetails != null && passwordMatches) {
//             System.out.println("\n✅ MANUAL AUTHENTICATION WOULD SUCCEED!");
//             System.out.println("   This means AuthService.login() should work with the manual authentication fix.");
//         } else {
//             System.err.println("\n❌ Manual authentication test failed");
//         }

//         System.out.println("======================================");
//         System.out.println("TEST COMPLETE");
//         System.out.println("======================================");
//     }
// }