package com.quackquack.auth.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.quackquack.auth.model.User;
import com.quackquack.auth.model.security.AuthResponse;
import com.quackquack.auth.model.security.UserPrincipal;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtUtil {

    private final ObjectMapper om;
    private final AES256 aes256;
    private final String REGEX = "^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$";

    @Value("${jwt.access_expiration}")
    private String accessExpiration;
    @Value("${jwt.refresh_expiration}")
    private String refreshExpiration;

    public boolean isValid(String token) {
        if (!isJwt(token)) return false;
        try {
            return isValid(token, alg(token));
        } catch (JsonProcessingException e) {
            return false;
        }
    }
    public Authentication getAuthentication(String token) {
        Claims body = parseClaims(token).getBody();
        String name = getNameFromToken(body);
        List<String> rolesMap = getRoleFromToken(body);
        return new UsernamePasswordAuthenticationToken(
                UserPrincipal.builder().name(name).build(),
                null,
                rolesMap.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );
    }

    private boolean isValid(String token, String alg) {
        Key publicKey = KeyUtil.signingKey(SignatureAlgorithm.forName(alg));
        JwtParser parser = Jwts.parserBuilder().setSigningKey(publicKey).build();
        return parser.isSigned(token);
    }

    private boolean isJwt(String token) {
        return token != null && !token.isBlank() && token.matches(REGEX);
    }

    private String alg(String token) throws JsonProcessingException {
        if (!isJwt(token)) return null;

        String[] chunks = token.split("\\.");
        String header = new String(Base64.getUrlDecoder().decode(chunks[0]), StandardCharsets.UTF_8);
        Map<String, Object> headerMap = om.readValue(header, Map.class);
        return (String) headerMap.get("alg");
    }

    public AuthResponse generate(User user) {
        try {
            long longIssuedAt = ZonedDateTime.now(TimeZone.getTimeZone("UTC").toZoneId()).toInstant().toEpochMilli();
            Date issuedAt = new Date(longIssuedAt);
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRoles());
            String subject  = encrypt(user.getUsername());
            String accessToken = generateToken(subject, claims, issuedAt, new Date(longIssuedAt + Long.parseLong(accessExpiration)));
            String refreshToken = generateToken(subject, claims, issuedAt, new Date(longIssuedAt + Long.parseLong(refreshExpiration)));
            return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .issuedAt(issuedAt)
                .build();
        }  catch (Exception e) {
            log.error(e.toString());
        }
        throw new UnsupportedJwtException("Cannot generate jwt");
    }
    private String generateToken(String subject, Map<String, Object> claims, Date issuedAt, Date expiration){
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.ES256;
        Key signingKey = KeyUtil.signingKey(signatureAlgorithm);
        if (signingKey == null) throw new JwtException("Not found signingKey for " + signatureAlgorithm.name());
        return Jwts.builder()
            .setHeaderParam("typ", "JWT")
            .setIssuer("quack")
            .setSubject(subject)
            .setIssuedAt(issuedAt)
            .setExpiration(expiration)
            .signWith(signingKey, signatureAlgorithm)
            .addClaims(claims)
            .compact();
    }

    public Jws<Claims> parseClaims(String token) {
        String alg="";
        try {
            alg = alg(token);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        Key publicKey = KeyUtil.parseKey((SignatureAlgorithm.forName(alg)));
        JwtParser parser = Jwts.parserBuilder().setSigningKey(publicKey).build();
        return parser.parseClaimsJws(token);
    }

    public String getNameFromToken(Claims body) {
        return body.getSubject();
    }

    public List<String> getRoleFromToken(Claims body) {
        return body.get("role", List.class);
    }

    public String encrypt(String text) throws Exception{
        return aes256.encrypt(text);
    }
    public String decrypt(String text) throws Exception{
        return aes256.decrypt(text);
    }

}
