package com.G14.aes.aes_backend.controller;

import com.G14.aes.aes_backend.entity.EncryptionRecord;
import com.G14.aes.aes_backend.entity.User;
import com.G14.aes.aes_backend.service.EncryptionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin("*")
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DashboardController {

    private final EncryptionService encryptionService;


    // --- History endpoints used by Dashboard.tsx ---

    @GetMapping("/history")
    public ResponseEntity<List<EncryptionRecord>> getHistory(Authentication authentication) {
        String email = getCurrentUserEmail(authentication);
        List<EncryptionRecord> history = encryptionService.getHistoryForUser(email);
        return ResponseEntity.ok(history);
    }

    @DeleteMapping("/history/{id}")
    public ResponseEntity<Void> deleteRecord(@PathVariable Long id, Authentication authentication) {
        String email = getCurrentUserEmail(authentication);
        encryptionService.deleteRecord(email, id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/history/all")
    public ResponseEntity<Void> deleteAll(Authentication authentication) {
        String email = getCurrentUserEmail(authentication);
        encryptionService.deleteAllForUser(email);
        return ResponseEntity.noContent().build();
    }

    private String getCurrentUserEmail(Authentication authentication) {
        if (authentication == null) {
            throw new RuntimeException("Unauthenticated");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof User user) {
            return user.getEmail();
        }
        // Fallback in case principal is just the email string
        return authentication.getName();
    }
}
