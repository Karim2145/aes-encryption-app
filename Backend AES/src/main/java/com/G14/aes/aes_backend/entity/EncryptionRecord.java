package com.G14.aes.aes_backend.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "encryption_history")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EncryptionRecord {
    // the format for the encryption history seen in the dashboard
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Algorithm used, e.g. "AES-128", "AES-192", "AES-256".
     */
    @Column(nullable = false)
    private String algorithm;

    /**
     * Mode used, e.g. "ECB", "CBC", "CFB", "OFB", "CTR".
     */
    @Column(nullable = false)
    private String mode;

    /**
     * Plaintext as UTF-8 text.
     */
    @Column(columnDefinition = "TEXT")
    private String plaintext;

    /**
     * Ciphertext as hex string (entire message).
     */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String ciphertext;

    /**
     * Hex representation of the key used (optional).
     */
    @Column(name = "key_used")
    private String keyUsed;

    /**
     * Email of the user that performed the operation.
     */
    @Column(name = "user_email", nullable = false)
    private String userEmail;

    /**
     * Number of 16-byte blocks processed.
     */
    @Column(name = "block_count")
    private Integer blockCount;

    /**
     * Timestamp when the record was created.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "operation", length = 16, nullable = false)
    private String operation;

    @Column(name = "iv_used")
    private String ivUsed;

    @Column(name = "ctr_used")
    private String ctrUsed;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
