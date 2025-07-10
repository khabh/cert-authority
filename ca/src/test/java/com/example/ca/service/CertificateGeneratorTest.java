package com.example.ca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.example.ca.exception.CaException;
import com.example.ca.service.command.CertificateGenerateCommand;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CertificateGeneratorTest {

    private final Instant fixedInstant = Instant.parse("2025-07-10T00:00:00Z");
    private final Clock fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC);
    private final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(new BouncyCastleProvider());
    private final JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());

    private CertificateGenerator generator;
    private int validityDays;
    private KeyPair keyPair;
    private CertificateGenerateCommand command;

    @BeforeEach
    void setUp() throws Exception {
        generator = new CertificateGenerator(fixedClock, contentSignerBuilder, certificateConverter);
        keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        validityDays = 365;
        command = CertificateGenerateCommand.builder()
                                            .issuer(new X500Name("CN=Root,O=ExampleOrg,C=KR"))
                                            .subject(new X500Name("CN=Leaf,O=ExampleOrg,C=KR"))
                                            .subjectPublicKey(keyPair.getPublic())
                                            .issuerPrivateKey(keyPair.getPrivate())
                                            .validityDays(validityDays)
                                            .build();
    }

    @Test
    @DisplayName("인증서 생성 시 NotBefore 날짜가 고정된 Clock와 일치해야 한다.")
    void generateCertificate1() {
        X509Certificate cert = generator.generateCertificate(command);

        assertThat(cert.getNotBefore().toInstant()).isEqualTo(fixedInstant);
    }

    @Test
    @DisplayName("인증서 생성 시 NotAfter 날짜가 유효기간만큼 더해진 날짜여야 한다.")
    void generateCertificate2() {
        X509Certificate cert = generator.generateCertificate(command);

        assertThat(cert.getNotAfter().toInstant()).isEqualTo(fixedInstant.plus(validityDays, ChronoUnit.DAYS));
    }

    @Test
    @DisplayName("인증서 생성 시 Issuer DN이 올바르게 설정되어야 한다.")
    void generateCertificate3() {
        X509Certificate cert = generator.generateCertificate(command);

        assertThat(cert.getIssuerX500Principal().getName()).contains("CN=Root")
                                                           .contains("O=ExampleOrg")
                                                           .contains("C=KR");
    }

    @Test
    @DisplayName("인증서 생성 시 Subject DN이 올바르게 설정되어야 한다.")
    void generateCertificate4() {
        X509Certificate cert = generator.generateCertificate(command);

        assertThat(cert.getSubjectX500Principal().getName()).contains("CN=Leaf")
                                                            .contains("O=ExampleOrg")
                                                            .contains("C=KR");
    }

    @Test
    @DisplayName("인증서 생성 시 공개키가 KeyPair의 공개키와 일치해야 한다.")
    void generateCertificate5() {
        X509Certificate cert = generator.generateCertificate(command);

        assertThat(cert.getPublicKey()).isEqualTo(keyPair.getPublic());
    }

    @Test
    @DisplayName("ContentSigner 생성 중 예외가 발생하면 CaException이 발생한다.")
    void generateCertificate6() throws Exception {
        JcaContentSignerBuilder mockSignerBuilder = mock(JcaContentSignerBuilder.class);
        when(mockSignerBuilder.build(any())).thenThrow(new OperatorCreationException("Mock failure"));

        CertificateGenerator brokenGenerator = new CertificateGenerator(fixedClock, mockSignerBuilder, certificateConverter);

        assertThatThrownBy(() -> brokenGenerator.generateCertificate(command))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("인증서 서명자 생성에 실패했습니다.");
    }

    @Test
    @DisplayName("X.509 인증서 변환 중 예외가 발생하면 CaException이 발생한다.")
    void generateCertificate7() throws Exception {
        JcaX509CertificateConverter mockConverter = mock(JcaX509CertificateConverter.class);
        when(mockConverter.getCertificate(any())).thenThrow(new CertificateException("Mock failure"));

        CertificateGenerator brokenGenerator = new CertificateGenerator(fixedClock, contentSignerBuilder, mockConverter);

        assertThatThrownBy(() -> brokenGenerator.generateCertificate(command))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("X.509 인증서 변환에 실패했습니다.");
    }
}