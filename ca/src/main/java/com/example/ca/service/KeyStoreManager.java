package com.example.ca.service;

import com.example.ca.domain.CaType;
import com.example.ca.exception.CaException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
public class KeyStoreManager {

    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss", Locale.KOREA);

    private final char[] password = "userpin".toCharArray();
    private final KeyStore keyStore;

    public String setRootKeyEntry(PrivateKey privateKey, Certificate certificate) {
        return setKeyEntry(privateKey, new Certificate[]{certificate}, CaType.ROOT);
    }

    public String setSubKeyEntry(PrivateKey privateKey, Certificate[] certificates) {
        return setKeyEntry(privateKey, certificates, CaType.SUB);
    }

    public String setKeyEntry(PrivateKey privateKey, Certificate[] chain, CaType caType) {
        String alias = generateAlias(caType);
        setKeyEntry(alias, privateKey, chain);

        return alias;
    }

    public void setKeyEntry(String alias, PrivateKey privateKey, Certificate[] chain) {
        try {
            keyStore.setKeyEntry(
                alias,
                privateKey,
                password,
                chain
            );
        } catch (KeyStoreException e) {
            throw new CaException("key 저장에 실패했습니다.");
        }
    }

    public PrivateKey getPrivateKey(String alias) {
        try {
            PrivateKey key = (PrivateKey) keyStore.getKey(alias, password);
            Assert.notNull(key, alias + " has no private key.");

            return key;
        } catch (Exception e) {
            throw new CaException("Failed to retrieve private key", e);
        }
    }

    public void removeKeyEntry(String alias) {
        try {
            keyStore.deleteEntry(alias);
        } catch (Exception e) {
            throw new CaException("Failed to remove key entry", e);
        }
    }

    private String generateAlias(CaType caType) {
        String timestamp = java.time.LocalDateTime.now().format(TIME_FORMATTER);
        String uuid = UUID.randomUUID().toString().substring(0, 5);

        return String.format("%s-%s-%s", caType, uuid, timestamp);
    }

    public void printAll() {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                KeyStore.Entry entry = keyStore.getEntry(alias, null);
                System.out.printf("alias=%s, class=%s%n", alias, entry.getClass().getSimpleName());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void removeAll() {
        try {
            List<String> aliasList = Collections.list(keyStore.aliases());

            for (String alias : aliasList) {
                try {
                    keyStore.deleteEntry(alias);
                    System.out.println("Deleted: " + alias);
                } catch (Exception ex) {
                    System.err.println("Failed to delete alias " + alias + ": " + ex.getMessage());
                    ex.printStackTrace();
                }
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to remove all entries from KeyStore", e);
        }
    }
}
