// src/main/java/com/G14/aes/aes_backend/dto/MultiBlockEncryptionBlockResultDto.java
package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class MultiBlockEncryptionBlockResultDto {

    private int blockIndex;               // 0-based
    private String plaintextBlockHex;     // 16-byte block, padded
    private String ciphertextBlockHex;    // final ciphertext block (mode output)
    private AESEncryptionResultDto aesResult; // full step trace
}
