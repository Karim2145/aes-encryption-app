package com.G14.aes.aes_backend.service.impl;

import com.G14.aes.aes_backend.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Service
public class JwtServiceImpl implements JwtService {

    /**
     * NOTE: for production move this secret to configuration (env / config server)
     * and make it at least 256‑bit for HS256.
     */
    private static final String SECRET = "super-long-secret-key-change-me-12345678901234567890";

    // e.g. 25 minutes access token, 1 day refresh token
    private static final long ACCESS_TOKEN_EXP_MS = 25 * 60 * 1000L;
    private static final long REFRESH_TOKEN_EXP_MS = 24 * 60 * 60 * 1000L;

    private final Key key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));

    @Override
    public String generateAccessToken(String email) {
        return generateToken(email, ACCESS_TOKEN_EXP_MS);
    }

    @Override
    public String generateRefreshToken(String email) {
        return generateToken(email, REFRESH_TOKEN_EXP_MS);
    }

    private String generateToken(String email, long expMs) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expMs);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key)
                .compact();
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            getClaims(token);
            return true;
        } catch (ExpiredJwtException ex) {
            return false;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public String extractEmail(String token) {
        return getClaims(token).getSubject();
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
