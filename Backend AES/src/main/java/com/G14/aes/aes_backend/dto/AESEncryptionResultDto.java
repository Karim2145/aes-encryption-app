// src/main/java/com/G14/aes/aes_backend/dto/AESEncryptionResultDto.java
package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

/**
 * Per-block AES details used by the visualizer.
 *
 * For encryption modes:
 *  - "ciphertext" = final AES block output (keystream or ciphertext depending on mode)
 * For decryption in streaming modes:
 *  - we still store the AES block output; frontend labels it appropriately.
 */
@Getter
@Setter
@NoArgsConstructor
public class AESEncryptionResultDto {

    private List<Integer> ciphertext; // bytes of AES primitive output
    private List<AESRoundStepDto> steps;
}

