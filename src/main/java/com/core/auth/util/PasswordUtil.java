package com.core.auth.util;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class PasswordUtil {
    
    private final Argon2 argon2;
    
    public PasswordUtil() {
        this.argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    }
    
    public String hashPassword(String password) {
        try {
            // Parameters: iterations, memory, parallelism, salt length, hash length
            return argon2.hash(10, 65536, 2, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }
    
    public boolean verifyPassword(String hash, String password) {
        try {
            return argon2.verify(hash, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }
    
    public boolean needsRehash(String hash) {
        return argon2.needsRehash(hash, 10, 65536, 2);
    }
}