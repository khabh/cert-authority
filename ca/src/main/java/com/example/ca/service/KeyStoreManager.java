package com.example.ca.service;

import com.example.ca.domain.CaType;
import com.example.ca.exception.CaException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

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

        return alias;
    }

    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password);
        } catch (Exception e) {
            throw new CaException("Failed to retrieve private key", e);
        }
    }

    private String generateAlias(CaType caType) {
        String timestamp = java.time.LocalDateTime.now().format(TIME_FORMATTER);
        String uuid = UUID.randomUUID().toString().substring(0, 5);

        return String.format("%s-%s-%s", caType, uuid, timestamp);
    }
}
