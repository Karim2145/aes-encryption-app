// src/main/java/com/G14/aes/aes_backend/dto/AESRoundStepDto.java
package com.G14.aes.aes_backend.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Single visual step: SubBytes, ShiftRows, MixColumns, AddRoundKey, etc.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AESRoundStepDto {

    private int round;        // 0..Nr, or Nr..0 for decryption
    private String step;      // "Round 1 - SubBytes", etc.
    private int[][] state;    // 4x4 matrix [col][row]
    private int[][] roundKey; // 4x4 matrix [col][row] or null
}


