package com.example.ca.testutil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairFactory {

    private static final KeyPairGenerator keyGen;

    static {
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        keyGen.initialize(2048);
    }

    public static KeyPair generate() {
        return keyGen.generateKeyPair();
    }
}
