package com.G14.aes.aes_backend.auth;

import com.G14.aes.aes_backend.auth.dto.LoginDto;
import com.G14.aes.aes_backend.auth.dto.LoginResponse;
import com.G14.aes.aes_backend.auth.dto.SignUpDto;
import com.G14.aes.aes_backend.auth.dto.UserDto;
import com.G14.aes.aes_backend.entity.User;
import com.G14.aes.aes_backend.repository.UserRepository;
import com.G14.aes.aes_backend.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    // Simple but correct email validator
    private static final Pattern SIMPLE_EMAIL_REGEX =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");

    // Strong password validator:
    // Min 8 chars, upper, lower, digit, special
    private static final Pattern PASSWORD_REGEX =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public void signup(SignUpDto request) {

        // VALIDATE EMAIL
        if (!SIMPLE_EMAIL_REGEX.matcher(request.getEmail()).matches()) {
            throw new RuntimeException("Invalid email format.");
        }

        // VALIDATE PASSWORD
        if (!PASSWORD_REGEX.matcher(request.getPassword()).matches()) {
            throw new RuntimeException(
                    "Password must be 8+ chars, include uppercase, lowercase, digit, and special character."
            );
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email is already registered");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();

        userRepository.save(user);
    }

    public LoginResponse login(LoginDto request) {

        // Email validation also here
        if (!SIMPLE_EMAIL_REGEX.matcher(request.getEmail()).matches()) {
            throw new RuntimeException("Invalid email format.");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        UserDto userDto = new UserDto(user.getId(), user.getEmail());

        return new LoginResponse(accessToken, refreshToken, userDto);
    }
}
