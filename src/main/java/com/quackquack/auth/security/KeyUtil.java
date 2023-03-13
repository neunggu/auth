package com.quackquack.auth.security;

import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class KeyUtil {
    private KeyUtil() {}
    private static final Map<String, Key> signingKeyStore = new ConcurrentHashMap<>();
    private static final Map<String, Key> parseKeyStore = new ConcurrentHashMap<>();

    public static Key parseKey(SignatureAlgorithm signatureAlgorithm) {
        Key key = null;
        if (parseKeyStore.containsKey(signatureAlgorithm.name())) {
            key = parseKeyStore.get(signatureAlgorithm.name());
        }

        if (key != null) return key;

        try {
            String content;
            PemReader pemReader;
            X509EncodedKeySpec spec;
            KeyFactory kf;

            switch (signatureAlgorithm) {
                case ES256:
                    content = StreamUtils.copyToString(new ClassPathResource("jwt/es256/ec-public.pem").getInputStream(), StandardCharsets.UTF_8);
                    pemReader = new PemReader(new StringReader(content));
                    spec = new X509EncodedKeySpec(pemReader.readPemObject().getContent());
                    kf = KeyFactory.getInstance("EC");
                    key = kf.generatePublic(spec);
                    break;
                default:
                    throw new UnsupportedOperationException("Only support ES256");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        parseKeyStore.put(signatureAlgorithm.name(), key);
        return key;
    }

    public static Key signingKey(SignatureAlgorithm signatureAlgorithm) {
        Key key = null;
        if (signingKeyStore.containsKey(signatureAlgorithm.name())) {
            key = signingKeyStore.get(signatureAlgorithm.name());
        }

        if (key != null) return key;

        try {
            String content;
            PemReader pemReader;
            PKCS8EncodedKeySpec spec;
            KeyFactory kf;

            switch (signatureAlgorithm) {
                case ES256:
                    content = StreamUtils.copyToString(new ClassPathResource("jwt/es256/ec-private.pkcs8").getInputStream(), StandardCharsets.UTF_8);
                    pemReader = new PemReader(new StringReader(content));
                    spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
                    kf = KeyFactory.getInstance("EC");
                    key = kf.generatePrivate(spec);
                    break;
                default:
                    throw new UnsupportedOperationException("Only support ES256");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        signingKeyStore.put(signatureAlgorithm.name(), key);
        return key;
    }

}
