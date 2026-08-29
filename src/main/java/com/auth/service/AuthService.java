package com.auth.service;

import com.auth.dto.request.AuthRequest;
import com.auth.dto.request.RegisterRequest;
import com.auth.dto.response.RegisterResponse;
import com.auth.dto.response.AuthResponse;
import com.auth.model.User;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRoleRepository;
import com.auth.util.EnumStatus;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Service for handling user authentication and registration.
 */
@Service
public class AuthService {

    private final UserService userService;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthService(
        UserService userService,
        RoleRepository roleRepository,
        UserRoleRepository userRoleRepository,
        JwtService jwtService,
        PasswordEncoder passwordEncoder
    ) {
        this.userService = userService;
        this.roleRepository = roleRepository;
        this.userRoleRepository = userRoleRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Register a new user with the provided registration details.
     *
     * @param request the registration request containing user details
     * @return a Mono emitting RegisterResponse upon successful registration
     */
    @Transactional
    public Mono<RegisterResponse> register(RegisterRequest request) {
        return userService.existsByUsername(request.getUsername())
            .flatMap(exists -> exists 
                ? Mono.error(new RuntimeException("Username already exists")) 
                : Mono.just(false)
            )
            .flatMap(ignore -> userService.existsByEmail(request.getEmail()))
            .flatMap(exists -> exists 
                ? Mono.error(new RuntimeException("Email already exists")) 
                : Mono.just(false)
            )
            .flatMap(ignore -> {
                User user = new User(
                    request.getFirstName(),
                    request.getLastName(),
                    request.getUsername(),
                    passwordEncoder.encode(request.getPassword()),
                    request.getEmail()
                );
                user.setPhoneNumber(request.getPhoneNumber());
                return userService.save(user);
            })
            .flatMap(savedUser -> 
                roleRepository.findByName("USER")
                    .switchIfEmpty(Mono.error(new RuntimeException("USER role not found")))
                    .flatMap(role -> 
                        // manually insert into tbl_user_role
                        userRoleRepository.insertUserRole(savedUser.getId(), role.getId())
                            // Use map() to return RegisterResponse
                            .then(Mono.defer(() -> Mono.just(new RegisterResponse())))
                    )
            );
    }

    /**
     * Login user and generate JWT tokens.
     *
     * @param request the authentication request containing username and password
     * @return a Mono emitting AuthResponse containing access and refresh tokens
     */
    public Mono<AuthResponse> authenticate(AuthRequest request) {
        return userService.findByUsername(request.getUsername())
            .flatMap(userDetails -> {
                User user = (User) userDetails;
                if (EnumStatus.DEACTIVATED.getValue().equals(user.getStatus())) {
                    return Mono.error(new AccessDeniedException(
                        "Your account is inactive. Please contact the administrator."
                    ));
                }

                return passwordEncoder.matches(request.getPassword(), user.getPassword())
                    ? Mono.just(user)
                    : Mono.empty();
            })
            .switchIfEmpty(Mono.error(new RuntimeException("Invalid credentials")))
            .flatMap(user -> {
                String accessToken = jwtService.generateAccessToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);
                Long expiresIn = jwtService.extractExpiration(accessToken).getTime() - System.currentTimeMillis();
                return Mono.just(new AuthResponse(accessToken, refreshToken, expiresIn));
            });
    }

    /**
     * Refresh access token using refresh token.
     *
     * @param refreshToken the refresh token
     * @return a Mono emitting AuthResponse containing new access and refresh tokens
     */
    public Mono<AuthResponse> refreshToken(String refreshToken) {
        if (!jwtService.validateToken(refreshToken)) {
            return Mono.error(new RuntimeException("Invalid refresh token"));
        }

        String username = jwtService.extractUsername(refreshToken);

        return userService.findByUsername(username)
            .flatMap(user -> {
                String newAccessToken = jwtService.generateAccessToken(user);
                String newRefreshToken = jwtService.generateRefreshToken(user);
                Long expiresIn = jwtService.extractExpiration(newAccessToken).getTime() - System.currentTimeMillis();
                return Mono.just(new AuthResponse(newAccessToken, newRefreshToken, expiresIn));
            });
    }

    /**
     * Logout user and invalidate tokens.
     *
     * @param accessToken the access token to be revoked
     * @param refreshToken the refresh token to be revoked
     * @return a Mono indicating completion of logout operation
     */
    public Mono<Void> logout(String accessToken, String refreshToken) {
        jwtService.revokeUser(jwtService.extractUsername(accessToken));
        jwtService.revokeToken(accessToken);
        jwtService.revokeToken(refreshToken);
        return Mono.empty();
    }
}