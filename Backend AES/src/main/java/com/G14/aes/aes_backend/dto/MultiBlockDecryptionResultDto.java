package com.G14.aes.aes_backend.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class MultiBlockDecryptionResultDto {

    private String mode;
    private List<MultiBlockDecryptionBlockResultDto> blockResults;
    private String paddingDescription;
    private String plaintextHex; // entire message hex (unpadded)
}
