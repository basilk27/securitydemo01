package com.mbsystems.securitydemo01.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Data
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PUBLIC, force = true)
public final class UsernameAndPasswordAuthenticationRequest {
    private final String username;
    private final String password;
}
