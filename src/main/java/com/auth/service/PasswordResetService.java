package com.auth.service;

import com.auth.model.User;
import com.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Roeurt Kesei
 * Service for handling password reset functionality, including sending verification codes
 * and resetting passwords.
 */
@Service
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final Duration codeLifetime;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, ResetCode> resetCodes = new ConcurrentHashMap<>();

    public PasswordResetService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JavaMailSender mailSender,
            @Value("${app.password-reset.from:${spring.mail.username:}}") String fromAddress,
            @Value("${app.password-reset.code-lifetime:10m}") Duration codeLifetime
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.mailSender = mailSender;
        this.fromAddress = fromAddress;
        this.codeLifetime = codeLifetime;
    }

    public Mono<Void> sendCode(String email) {
        return userRepository.findByEmailAndIsDeletedFalse(email)
                .flatMap(user -> {
                    String code = String.format("%04d", secureRandom.nextInt(10000));
                    resetCodes.put(email, new ResetCode(code, Instant.now().plus(codeLifetime)));
                    return sendEmail(user, code);
                })
                .then();
    }

    public Mono<Void> resetPassword(String email, String code, String newPassword, String confirmNewPassword) {
        if (!newPassword.equals(confirmNewPassword)) {
            return Mono.error(new IllegalArgumentException("New password and confirmation do not match"));
        }

        ResetCode resetCode = resetCodes.get(email);
        if (resetCode == null || resetCode.expiresAt().isBefore(Instant.now()) || !resetCode.code().equals(code)) {
            return Mono.error(new IllegalArgumentException("Invalid or expired verification code"));
        }

        return userRepository.findByEmailAndIsDeletedFalse(email)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("User not found")))
                .flatMap(user -> {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    user.setModifiedAt(java.time.LocalDateTime.now());
                    return userRepository.save(user);
                })
                .doOnSuccess(ignored -> resetCodes.remove(email))
                .then();
    }

    private Mono<Void> sendEmail(User user, String code) {
        return Mono.fromRunnable(() -> {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(user.getEmail());
            if (!fromAddress.isBlank()) {
                message.setFrom(fromAddress);
            }
            message.setSubject("Password reset verification code");
            message.setText("Your password reset verification code is " + code + ". It expires in "
                    + codeLifetime.toMinutes() + " minutes.");
            mailSender.send(message);
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    private record ResetCode(String code, Instant expiresAt) {}
}