package com.mbsystems.securitydemo01.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

@Configuration
public class JwtSecretKey {

    private final JwtConfig jwtConfig;

    public JwtSecretKey(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    @Bean
    public Key getHmacKey() {
        return new SecretKeySpec(
                Base64.getDecoder().decode(this.jwtConfig.getSecretKey()),
                SignatureAlgorithm.HS256.getJcaName());
    }

}
