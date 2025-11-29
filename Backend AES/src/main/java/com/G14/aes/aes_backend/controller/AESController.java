package com.G14.aes.aes_backend.controller;

import com.G14.aes.aes_backend.dto.*;
import com.G14.aes.aes_backend.entity.User;
import com.G14.aes.aes_backend.aes.AESService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/aes")
@CrossOrigin("*")
@RequiredArgsConstructor
public class AESController {

    private final AESService aesService;

    @PostMapping("/encrypt-full-text")
    public ResponseEntity<MultiBlockEncryptionResultDto> encryptFullText(
            @RequestBody EncryptFullTextRequest request,
            Authentication authentication
    ) {
        String email = getCurrentUserEmail(authentication);
        MultiBlockEncryptionResultDto result = aesService.encryptFullText(request, email);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/decrypt-full-text")
    public ResponseEntity<MultiBlockDecryptionResultDto> decryptFullText(
            @RequestBody DecryptFullTextRequest request,
            Authentication authentication
    ) {
        String email = getCurrentUserEmail(authentication);
        MultiBlockDecryptionResultDto result = aesService.decryptFullText(request, email);
        return ResponseEntity.ok(result);
    }

    private String getCurrentUserEmail(Authentication authentication) {
        if (authentication == null) {
            throw new RuntimeException("Unauthenticated");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof User user) {
            return user.getEmail();
        }
        return authentication.getName();
    }
}
