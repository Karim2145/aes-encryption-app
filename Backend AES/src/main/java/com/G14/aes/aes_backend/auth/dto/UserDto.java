package com.G14.aes.aes_backend.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserDto { // user identifier
    private Long id;
    private String email;
}
