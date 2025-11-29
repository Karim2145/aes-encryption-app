package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class MultiBlockDecryptionBlockResultDto {

    private int blockIndex;
    private String ciphertextBlockHex;
    private String plaintextBlockHex;
    private AESEncryptionResultDto aesResult; // "ciphertext" field holds plaintext bytes
}
