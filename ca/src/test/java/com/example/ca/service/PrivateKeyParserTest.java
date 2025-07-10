package com.example.ca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.ca.exception.CaException;
import com.example.ca.testutil.KeyPairFactory;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PrivateKeyParserTest {

    private final PrivateKeyParser privateKeyParser = new PrivateKeyParser(new JcaPEMKeyConverter());

    @Test
    @DisplayName("PEM 형식의 개인키를 파싱할 수 있다.")
    void parsePrivateKey1() throws Exception {
        KeyPair keyPair = KeyPairFactory.generate();

        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(keyPair.getPrivate());
        }
        String pem = sw.toString();

        PrivateKey parsedKey = privateKeyParser.parsePrivateKey(pem);

        assertThat(parsedKey.getEncoded())
            .isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @Test
    @DisplayName("지원하지 않는 PEM 객체를 입력하면 예외가 발생한다.")
    void parsePrivateKey2() {
        String certPem = "-----BEGIN CERTIFICATE-----\nsdfskfdjsklfjdkdsjkdfj\n-----END CERTIFICATE-----";

        assertThatThrownBy(() -> privateKeyParser.parsePrivateKey(certPem))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("개인키 파싱에 실패했습니다.");
    }
}