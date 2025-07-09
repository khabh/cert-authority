package com.example.ca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import com.example.ca.domain.repository.CertificateAuthorityRepository;
import com.example.ca.exception.CaException;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class CertificateServiceTest {

    @Autowired
    CertificateService certificateService;

    @Autowired
    CertificateAuthorityRepository certificateAuthorityRepository;

    @BeforeEach
    void setUp() {
        certificateAuthorityRepository.deleteAll();
    }

    @Test
    @DisplayName("중복 DN으로 root CA 발급 시 예외가 발생한다.")
    void issueRootCertificate1() {
        DistinguishedName dn = DistinguishedName.builder()
                                                .commonName("Test CN")
                                                .countryName("KR")
                                                .build();

        CertificationAuthority ca = new CertificationAuthority(dn, "dummyPrivateKey");
        certificateAuthorityRepository.save(ca);

        RootCertificateIssueDto dto = new RootCertificateIssueDto(
            "Test CN", null, null, null, null, "KR"
        );

        assertThatThrownBy(() -> certificateService.issueRootCertificate(dto))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("해당 DN으로 등록된 root CA가 존재합니다.");
    }

    @Test
    @DisplayName("새로운 DN으로 root CA 발급 성공")
    void issueRootCertificate2() {
        RootCertificateIssueDto dto = new RootCertificateIssueDto(
            "Unique CN", null, null, null, null, "KR"
        );

        CertificateDto certDto = certificateService.issueRootCertificate(dto);

        assertThat(certDto).isNotNull();
        assertThat(certDto.certificate()).contains("-----BEGIN CERTIFICATE-----");
    }

    @Test
    @DisplayName("발급된 인증서의 subject와 issuer가 요청한 DN과 일치해야 한다")
    void issueRootCertificate3() throws Exception {
        RootCertificateIssueDto dto = new RootCertificateIssueDto(
            "Test CN", "Example Org", "IT Dept", "Seoul", "Seoul", "KR"
        );

        CertificateDto result = certificateService.issueRootCertificate(dto);

        String pem = result.certificate();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream pemStream = new ByteArrayInputStream(
            Base64.getDecoder().decode(pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "")
            )
        );
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(pemStream);

        assertThat(cert.getSubjectX500Principal().getName())
            .contains("CN=Test CN")
            .contains("O=Example Org")
            .contains("OU=IT Dept")
            .contains("L=Seoul")
            .contains("ST=Seoul")
            .contains("C=KR");

        assertThat(cert.getIssuerX500Principal().getName())
            .isEqualTo(cert.getSubjectX500Principal().getName());

        assertThat(cert.getNotBefore()).isBeforeOrEqualTo(new Date());
        assertThat(cert.getNotAfter()).isAfter(cert.getNotBefore());
    }
}