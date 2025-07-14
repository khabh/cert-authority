package com.example.ca.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import com.example.ca.domain.repository.CertificateAuthorityRepository;
import com.example.ca.exception.CaException;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import com.example.ca.testutil.CsrTestUtil;
import com.example.ca.testutil.GeneratedCsr;
import com.example.ca.testutil.PemUtils;
import com.example.ca.util.CertificateUtil;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CertificateServiceTest {

    @Autowired
    CertificateService certificateService;

    @Autowired
    KeyStoreManager keyStoreManager;

    @Autowired
    KeyStore keyStore;

    @Autowired
    CertificateAuthorityRepository certificateAuthorityRepository;

    @BeforeEach
    void setUp() {
        certificateAuthorityRepository.findAll()
                                      .stream()
                                      .map(CertificationAuthority::getAlias)
                                      .forEach(alias -> {
                                          try {
                                              if (keyStore.containsAlias(alias)) {
                                                  keyStore.deleteEntry(alias);
                                              }
                                          } catch (Exception e) {
                                              throw new RuntimeException(e);
                                          }
                                      });
        certificateAuthorityRepository.deleteAll();
    }

    @Test
    @DisplayName("중복 DN으로 root CA 발급 시 예외가 발생한다.")
    void issueRootCertificate1() {
        DistinguishedName dn = DistinguishedName.builder()
                                                .commonName("Test CN")
                                                .countryName("KR")
                                                .build();
        CertificationAuthority ca = new CertificationAuthority(dn, "dummyPrivateKey", "dummyCertificate");
        certificateAuthorityRepository.save(ca);
        RootCertificateIssueDto dto = new RootCertificateIssueDto(
            "Test CN", null, null, null, null, "KR"
        );

        assertThatThrownBy(() -> certificateService.issueRootCertificate(dto))
            .isInstanceOf(CaException.class)
            .hasMessageContaining("해당 DN으로 등록된 CA가 존재합니다.");
    }

    @Test
    @DisplayName("발급된 인증서의 subject와 issuer가 요청한 DN과 일치해야 한다.")
    void issueRootCertificate2() {
        RootCertificateIssueDto dto = new RootCertificateIssueDto(
            "Test CN", "Example Org", "IT Dept", "Seoul", "Seoul", "KR"
        );

        CertificateDto result = certificateService.issueRootCertificate(dto);

        X509Certificate cert = PemUtils.parseCertificateFromPem(result.certificate());
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

    @Test
    @DisplayName("CSR을 기반으로 인증서를 발급할 수 있다.")
    void issueRootCertificate3() {
        RootCertificateIssueDto rootDto = new RootCertificateIssueDto("CA Root", "AutoCrypt", "IT", "Seoul", "Seoul", "KR");
        certificateService.issueRootCertificate(rootDto);
        CertificationAuthority certificationAuthority = certificateAuthorityRepository.findAll().getFirst();
        X500Name issuerX500Name = certificationAuthority.getX500Name();
        Long certificationAuthorityId = certificationAuthority.getId();
        String subjectDn = "CN=LeafCert, OU=Dev, O=AutoCrypt, L=Seoul, ST=Seoul, C=KR";
        GeneratedCsr generatedCsr = CsrTestUtil.generateCsr(subjectDn);

        CertificateDto issued = certificateService.issueCertificate(
            new CertificateIssueDto(
                certificationAuthorityId,
                365,
                generatedCsr.csrPem()
            )
        );

        X509Certificate cert = PemUtils.parseCertificateFromPem(issued.certificate());
        X500Name actualSubject = new X500Name(cert.getSubjectX500Principal().getName());
        assertThat(actualSubject).isEqualTo(new X500Name(subjectDn));

        X500Name actualIssuer = new X500Name(cert.getIssuerX500Principal().getName());
        assertThat(actualIssuer).isEqualTo(issuerX500Name);
    }

    @Test
    @DisplayName("서브 인증서를 HSM을 통해 발급할 수 있다.")
    void issueSubCertificate() throws Exception {
        RootCertificateIssueDto rootDto = new RootCertificateIssueDto(
            "Root CN", "Root Org", "Root Unit", "Seoul", "Seoul", "KR"
        );
        certificateService.issueRootCertificate(rootDto);
        CertificationAuthority rootCa = certificateAuthorityRepository.findAll().getFirst();

        SubCertificateIssueDto subDto = new SubCertificateIssueDto(
            rootCa.getId(),
            "Sub CN", "Sub Org", "Sub Unit", "Seoul", "Seoul", "KR"
        );

        CertificateDto result = certificateService.issueSubCertificate(subDto);
        X509Certificate cert = PemUtils.parseCertificateFromPem(result.certificate());

        assertThat(cert.getSubjectX500Principal().getName())
            .contains("CN=Sub CN")
            .contains("O=Sub Org")
            .contains("OU=Sub Unit")
            .contains("C=KR");
        assertThat(new X500Name(cert.getIssuerX500Principal().getName()))
            .isEqualTo(rootCa.getX500Name());

        PublicKey rootPublicKey = CertificateUtil.getCertificate(rootCa.getCertificate()).getPublicKey();
        cert.verify(rootPublicKey);

        CertificationAuthority ca = certificateAuthorityRepository.findAll().getLast();
        assertThat(ca.getIssuerId()).isEqualTo(rootCa.getId());
        assertThat(keyStoreManager.getPrivateKey(ca.getAlias())).isNotNull();
    }
}