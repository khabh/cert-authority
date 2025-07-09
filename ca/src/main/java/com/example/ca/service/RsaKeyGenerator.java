package com.example.ca.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;

@Component
public class RsaKeyGenerator {

    private final KeyPairGenerator keyGen;

    public RsaKeyGenerator() throws NoSuchAlgorithmException {
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
    }

    public KeyPair generateKeyPair() {
        return keyGen.generateKeyPair();
    }
}