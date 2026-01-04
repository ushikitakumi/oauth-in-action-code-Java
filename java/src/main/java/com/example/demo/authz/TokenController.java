package com.example.demo.authz;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

@RestController
public class TokenController {

    private final SimpleAuthorizationController authController;
    private final RSAKey rsaKey;

    public TokenController(SimpleAuthorizationController authController, RSAKey rsaKey) {
        this.authController = authController;
        this.rsaKey = rsaKey;
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> token(@RequestParam MultiValueMap<String, String> paramMap,
                                   @RequestHeader(value = "Authorization", required = false) String authorization) throws Exception {
        String grantType = paramMap.getFirst("grant_type");
        if (!"authorization_code".equals(grantType)) {
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
        }

        String code = paramMap.getFirst("code");
        String username = authController.consumeCode(code);
        if (username == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant"));
        }

        // Create a simple signed JWT access token
        JWSSigner signer = new RSASSASigner(rsaKey.toPrivateKey());

        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer("http://localhost:9001")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("scope", "read")
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.getKeyID())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);

        String token = signedJWT.serialize();

        return ResponseEntity.ok(Map.of(
                "access_token", token,
                "token_type", "Bearer",
                "expires_in", 300
        ));
    }
}
