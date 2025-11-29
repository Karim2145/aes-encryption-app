package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class MultiBlockEncryptionResultDto {

    private String mode; // "ECB" / "CBC" / ...
    private List<MultiBlockEncryptionBlockResultDto> blockResults;
    private String paddingDescription;
    private String ciphertextHex; // entire message hex
}
