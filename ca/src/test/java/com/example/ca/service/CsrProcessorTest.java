package com.example.ca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.ca.exception.CaException;
import com.example.ca.testutil.CsrTestUtil;
import com.example.ca.testutil.GeneratedCsr;
import com.example.ca.testutil.KeyPairFactory;
import java.security.KeyPair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class CsrProcessorTest {

    private final JcaContentVerifierProviderBuilder verifierBuilder = new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider());
    private final CsrProcessor csrProcessor = new CsrProcessor(verifierBuilder);

    @Test
    @DisplayName("PEM을 파싱하여 서명을 검증한다.")
    void parseValidCsr1() {
        String dn = "CN=juha, OU=IT, O=organization, L=Gangnam-gu, ST=Seoul, C=KR";
        GeneratedCsr generated = CsrTestUtil.generateCsr(dn);

        PKCS10CertificationRequest parsedCsr = csrProcessor.parseValidCsr(generated.csrPem());

        X500Name expectedSubject = new X500Name(dn);
        assertThat(parsedCsr.getSubject()).isEqualTo(expectedSubject);
    }

    @Test
    @DisplayName("잘못된 CSR PEM 입력 시 예외가 발생한다.")
    void parseValidCsr2() {
        String invalidPem = "-----BEGIN INVALID CSR-----\nabc\n-----END INVALID CSR-----";

        assertThatThrownBy(() -> csrProcessor.parseValidCsr(invalidPem))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("CSR 파싱에 실패했습니다.");
    }

    @Test
    @DisplayName("CSR의 공개키와 서명자가 다르면 유효성 검증에 실패한다.")
    void parseValidCsr3() {
        KeyPair keyPairA = KeyPairFactory.generate();
        KeyPair keyPairB = KeyPairFactory.generate();
        String dn = "CN=juha, OU=IT, O=organization, L=Gangnam-gu, ST=Seoul, C=KR";

        GeneratedCsr invalidCsr = CsrTestUtil.generateCsr(dn, keyPairA.getPrivate(), keyPairB.getPublic());

        assertThatThrownBy(() -> csrProcessor.parseValidCsr(invalidCsr.csrPem()))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("CSR 서명 검증 중 오류가 발생했습니다.");
    }
}