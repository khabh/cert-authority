package com.example.ca.service;

import com.example.ca.exception.CaException;
import java.io.StringReader;
import java.security.PrivateKey;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PrivateKeyParser {

    private final JcaPEMKeyConverter converter;

    public PrivateKey parsePrivateKey(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object parsedObj = parser.readObject();
            if (parsedObj instanceof org.bouncycastle.openssl.PEMKeyPair keyPair) {
                return converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            }

            if (parsedObj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo) {
                return converter.getPrivateKey(privateKeyInfo);
            }

            throw new CaException("지원하지 않는 키 형식입니다.");
        } catch (Exception e) {
            throw new CaException("개인키 파싱에 실패했습니다.", e);
        }
    }
}
