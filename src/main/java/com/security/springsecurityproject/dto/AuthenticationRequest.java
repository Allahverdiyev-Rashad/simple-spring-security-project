package com.security.springsecurityproject.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationRequest {
    String email;
    String password;
}
