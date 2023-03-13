package com.quackquack.auth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
public class AES256 {
    @Value("${jwt.aes_key}")
    private String KEY;
    private String transformation;
    private String iv;
    private SecretKeySpec keySpec;
    private IvParameterSpec ivParameterSpec;

    @PostConstruct
    public void init() {
        this.transformation = "AES/CBC/PKCS5Padding";
        this.iv =KEY.repeat(16).substring(0, 16);
        this.keySpec = new SecretKeySpec(iv.getBytes(), "AES");
        this.ivParameterSpec = new IvParameterSpec(iv.getBytes());
    }

    public String encrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
        byte[] decodeBytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decodeBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
