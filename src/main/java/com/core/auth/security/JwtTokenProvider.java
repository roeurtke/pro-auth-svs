package com.core.auth.security;

import com.core.auth.config.JwtConfig;
import com.core.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    
    private final JwtConfig jwtConfig;
    
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));
    }
    
    public String generateAccessToken(User user, Collection<? extends GrantedAuthority> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("authorities", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(
                    Instant.now().plusMillis(jwtConfig.getAccessTokenExpiration())
                ))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("userId", user.getId())
                .claim("tokenType", "REFRESH")
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(
                    Instant.now().plusMillis(jwtConfig.getRefreshTokenExpiration())
                ))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public Claims validateAndParseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    
    public String getUsernameFromToken(String token) {
        return validateAndParseToken(token).getSubject();
    }
    
    public Long getUserIdFromToken(String token) {
        return validateAndParseToken(token).get("userId", Long.class);
    }
    
    public List<String> getAuthoritiesFromToken(String token) {
        Claims claims = validateAndParseToken(token);
        @SuppressWarnings("unchecked")
        List<String> authorities = claims.get("authorities", List.class);
        return authorities != null ? authorities : Collections.emptyList();
    }
    
    public LocalDateTime getExpirationDateFromToken(String token) {
        Date expiration = validateAndParseToken(token).getExpiration();
        return expiration.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }
    
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateAndParseToken(token);
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }
}