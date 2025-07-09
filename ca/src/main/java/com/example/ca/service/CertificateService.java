package com.example.ca.service;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import com.example.ca.domain.repository.CertificateAuthorityRepository;
import com.example.ca.exception.CaException;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CertificateService {

    private final RsaKeyGenerator keyGenerator;
    private final CertificateGenerator certificateGenerator;
    private final PemConverter pemConverter;
    private final CertificateAuthorityRepository certificateAuthorityRepository;

    @Transactional
    public CertificateDto issueRootCertificate(RootCertificateIssueDto rootCertificateIssueDto) {
        DistinguishedName distinguishedName = DistinguishedName.builder()
                                                               .commonName(rootCertificateIssueDto.commonName())
                                                               .organizationName(rootCertificateIssueDto.organizationName())
                                                               .organizationalUnitName(rootCertificateIssueDto.organizationalUnit())
                                                               .localityName(rootCertificateIssueDto.localityName())
                                                               .stateOrProvinceName(rootCertificateIssueDto.stateOrProvinceName())
                                                               .countryName(rootCertificateIssueDto.countryName())
                                                               .build();

        validateRootCaUnique(distinguishedName);

        X500Name subject = distinguishedName.toX500Name();
        KeyPair keyPair = keyGenerator.generateKeyPair();
        X509Certificate certificate = certificateGenerator.generateCertificate(
            subject,
            subject,
            keyPair,
            365
        );
        String certificatePem = pemConverter.convertCertificateToPem(certificate);

        saveCertificateAuthority(distinguishedName, keyPair.getPrivate());

        return new CertificateDto(certificatePem);
    }

    private void validateRootCaUnique(DistinguishedName distinguishedName) {
        if (certificateAuthorityRepository.existsByDistinguishedName(distinguishedName)) {
            throw new CaException("해당 DN으로 등록된 root CA가 존재합니다.");
        }
    }

    private void saveCertificateAuthority(DistinguishedName distinguishedName, PrivateKey privateKey) {
        String secretKey = pemConverter.convertPrivateKeyToPem(privateKey);
        CertificationAuthority certificationAuthority = new CertificationAuthority(distinguishedName, secretKey);
        certificateAuthorityRepository.save(certificationAuthority);
    }
}
