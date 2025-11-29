package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class EncryptFullTextRequest {
    //request for a full text encryption
    private String plaintext;    // full text to encrypt (Hex)
    private String keyHex;       // hex key as in frontend
    private int keySize;         // 128 / 192 / 256
    private String mode;         // "ECB", "CBC", "CFB", "OFB", "CTR"
    private String ivHex;
    private String ctrCounterHex; // optional, used only for CTR
}