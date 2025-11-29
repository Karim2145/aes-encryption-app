package com.G14.aes.aes_backend.service;

public interface JwtService {

    /**
     * Generate a short‑lived access token for the given user email.
     */
    String generateAccessToken(String email);

    /**
     * Generate a longer‑lived refresh token for the given user email.
     */
    String generateRefreshToken(String email);

    /**
     * Validate a JWT (access or refresh).
     */
    boolean isTokenValid(String token);

    /**
     * Extract the user email from a JWT.
     */
    String extractEmail(String token);
}
