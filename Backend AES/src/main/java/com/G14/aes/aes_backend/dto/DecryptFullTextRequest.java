package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class DecryptFullTextRequest {
    //request for a full text decryption
    private String ciphertextHex; // full ciphertext hex
    private String keyHex;        // hex key
    private int keySize;          // 128 / 192 / 256
    private String mode;
    private String ivHex; // "ECB", "CBC", "CFB", "OFB", "CTR"
    private String ctrCounterHex; // optional, only CTR
}

