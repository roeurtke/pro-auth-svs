package com.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import java.time.Duration;

/**
 * @author Roeurt Kesei
 * Service for generating and validating JWT tokens.
 */
@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.access-token.expiration}")
    private Duration accessTokenExpiration;
    
    @Value("${jwt.refresh-token.expiration}")
    private Duration refreshTokenExpiration;

    // Token revocation blacklist
    private final Set<String> revokedTokens = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Map<String, Date> revokedUsers = new ConcurrentHashMap<>();
    
    private Key getSigningKey() {
        byte[] keyBytes = secret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    /**
     * Extracts the username from the JWT token.
     *
     * @param token the JWT token
     * @return the username extracted from the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    /**
     * Extracts the expiration date from the JWT token.
     *
     * @param token the JWT token
     * @return the expiration date extracted from the token
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    /**
     * Extracts a specific claim from the JWT token using the provided claims resolver function.
     *
     * @param token the JWT token
     * @param claimsResolver a function to extract a specific claim from the Claims object
     * @param <T> the type of the claim to be extracted
     * @return the extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    /**
     * Extracts all claims from the JWT token.
     *
     * @param token the JWT token
     * @return the Claims object containing all claims extracted from the token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
    
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Creates a JWT token with the specified claims, subject, and expiration duration.
     *
     * @param claims the claims to be included in the token
     * @param subject the subject (username) of the token
     * @param expiration the duration after which the token will expire
     * @return the generated JWT token as a String
     */
    private String createToken(Map<String, Object> claims, String subject, Duration expiration) {
    return Jwts.builder()
        .setClaims(claims)
        .setSubject(subject)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + expiration.toMillis()))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
    }
    
    /**
     * Generates an access token for the given user details.
     *
     * @param userDetails the user details for which the access token is generated
     * @return the generated access token as a String
     */
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        
        // Add roles and permissions to claims
        claims.put("roles", userDetails.getAuthorities().stream()
            .filter(authority -> authority.getAuthority().startsWith("ROLE_"))
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        
        claims.put("permissions", userDetails.getAuthorities().stream()
            .filter(authority -> !authority.getAuthority().startsWith("ROLE_"))
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        
        return createToken(claims, userDetails.getUsername(), accessTokenExpiration);
    }
    
    /**
     * Generates a refresh token for the given user details.
     *
     * @param userDetails the user details for which the refresh token is generated
     * @return the generated refresh token as a String
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername(), refreshTokenExpiration);
    }
    
    /**
     * Validates the JWT token against the provided user details.
     *
     * @param token the JWT token to be validated
     * @param userDetails the user details to validate against
     * @return true if the token is valid and matches the user details, false otherwise
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenRevoked(token) && !isTokenExpired(token));
    }
    
    /**
     * Validates the JWT token for revocation and expiration.
     *
     * @param token the JWT token to be validated
     * @return true if the token is valid, false otherwise
     */
    public Boolean validateToken(String token) {
        try {
            if (isTokenRevoked(token) || isUserTokenRevoked(token)) {
                return false;
            }
            if (isTokenExpired(token)) {
                throw new ExpiredJwtException(null, null, "Token has expired");
            }
            return true;
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Access token has expired. Please refresh your token.", e);
        } catch (Exception e) {
            throw new RuntimeException("Invalid access token.", e);
        }
    }

    /**
     * Revokes the specified JWT token by adding it to the revoked tokens set.
     *
     * @param token the JWT token to be revoked
     */
    public void revokeToken(String token) {
        if (token != null) {
            revokedTokens.add(token);
        }
    }

    /**
     * Checks if the specified JWT token has been revoked.
     *
     * @param token the JWT token to check
     * @return true if the token is revoked, false otherwise
     */
    public boolean isTokenRevoked(String token) {
        return token != null && revokedTokens.contains(token);
    }

    /**
     * Revokes all tokens associated with the specified username by adding the username to the revoked users map.
     *
     * @param username the username whose tokens are to be revoked
     */
    public void revokeUser(String username) {
        if (username != null) {
            revokedUsers.put(username, new Date());
        }
    }

    /**
     * Checks if the tokens associated with the specified username have been revoked.
     *
     * @param token the JWT token to check
     * @return true if the user's tokens are revoked, false otherwise
     */
    private boolean isUserTokenRevoked(String token) {
        String username = extractUsername(token);
        Date revokedAt = revokedUsers.get(username);
        Date issuedAt = extractClaim(token, Claims::getIssuedAt);
        return revokedAt != null && issuedAt != null && !issuedAt.after(revokedAt);
    }
}