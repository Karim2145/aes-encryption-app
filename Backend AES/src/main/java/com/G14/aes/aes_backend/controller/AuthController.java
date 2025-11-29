package com.G14.aes.aes_backend.controller;

import com.G14.aes.aes_backend.auth.AuthService;
import com.G14.aes.aes_backend.auth.dto.LoginDto;
import com.G14.aes.aes_backend.auth.dto.LoginResponse;
import com.G14.aes.aes_backend.auth.dto.MessageResponse;
import com.G14.aes.aes_backend.auth.dto.SignUpDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@CrossOrigin("*") // React runs on another port during development
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> signup(@RequestBody SignUpDto request) {
        authService.signup(request);
        return ResponseEntity.ok(new MessageResponse("User registered successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginDto request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Stateless logout endpoint – the frontend simply drops tokens,
     * but we accept the refresh token payload so the API call succeeds.
     */
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(@RequestBody(required = false) Map<String, String> body) {
        // In a more advanced setup you'd blacklist the refresh token here.
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }
}
