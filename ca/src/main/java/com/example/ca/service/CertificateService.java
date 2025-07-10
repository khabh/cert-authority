package com.example.ca.service;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import com.example.ca.domain.repository.CertificateAuthorityRepository;
import com.example.ca.exception.CaException;
import com.example.ca.service.command.CertificateGenerateCommand;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.CertificationAuthorityDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CertificateService {

    private final RsaKeyGenerator keyGenerator;
    private final CertificateGenerator certificateGenerator;
    private final CsrProcessor csrProcessor;
    private final PrivateKeyParser privateKeyParser;
    private final CertificateAuthorityRepository certificateAuthorityRepository;

    @Transactional
    public CertificateDto issueCertificate(CertificateIssueDto certificateIssueDto) {
        PKCS10CertificationRequest csr = csrProcessor.parseValidCsr(certificateIssueDto.csr());
        CertificationAuthority ca = findCertificationAuthority(certificateIssueDto.certificateAuthorityId());
        CertificateGenerateCommand command = createCommand(certificateIssueDto, ca, csr);
        X509Certificate cert = certificateGenerator.generateCertificate(command);
        String certPem = toPem(cert);

        return new CertificateDto(certPem);
    }

    @Transactional
    public CertificateDto issueRootCertificate(RootCertificateIssueDto rootCertificateIssueDto) {
        DistinguishedName distinguishedName = dtoToDistinguishedName(rootCertificateIssueDto);
        validateRootCaUnique(distinguishedName);

        X500Name subject = distinguishedName.toX500Name();
        KeyPair keyPair = keyGenerator.generateKeyPair();
        CertificateGenerateCommand command = CertificateGenerateCommand.builder()
                                                                       .issuer(subject)
                                                                       .subject(subject)
                                                                       .issuerPrivateKey(keyPair.getPrivate())
                                                                       .subjectPublicKey(keyPair.getPublic())
                                                                       .validityDays(365)
                                                                       .build();
        X509Certificate certificate = certificateGenerator.generateCertificate(command);
        String certificatePem = toPem(certificate);

        saveCertificateAuthority(distinguishedName, keyPair.getPrivate());

        return new CertificateDto(certificatePem);
    }

    public List<CertificationAuthorityDto> findAllCertificationAuthorities() {
        return certificateAuthorityRepository.findAll()
                                             .stream()
                                             .map(CertificationAuthorityDto::of)
                                             .toList();
    }

    private void saveCertificateAuthority(DistinguishedName distinguishedName, PrivateKey privateKey) {
        String secretKey = toPem(privateKey);
        CertificationAuthority certificationAuthority = new CertificationAuthority(distinguishedName, secretKey);
        certificateAuthorityRepository.save(certificationAuthority);
    }

    private CertificateGenerateCommand createCommand(
        CertificateIssueDto certificateIssueDto,
        CertificationAuthority ca,
        PKCS10CertificationRequest csr) {
        PublicKey subjectKey;
        try {
            subjectKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new CaException("공개키 파싱에 실패했습니다.");
        }

        return CertificateGenerateCommand.builder()
                                         .issuer(ca.getX500Name())
                                         .subject(csr.getSubject())
                                         .subjectPublicKey(subjectKey)
                                         .issuerPrivateKey(privateKeyParser.parsePrivateKey(ca.getSecretKey()))
                                         .validityDays(certificateIssueDto.validityDays())
                                         .build();
    }

    private void validateRootCaUnique(DistinguishedName distinguishedName) {
        if (certificateAuthorityRepository.existsByDistinguishedName(distinguishedName)) {
            throw new CaException("해당 DN으로 등록된 root CA가 존재합니다.");
        }
    }

    private CertificationAuthority findCertificationAuthority(Long id) {
        return certificateAuthorityRepository.findById(id)
                                             .orElseThrow(() -> new CaException("해당 ID의 CA가 존재하지 않습니다."));
    }

    private DistinguishedName dtoToDistinguishedName(RootCertificateIssueDto rootCertificateIssueDto) {
        return DistinguishedName.builder()
                                .commonName(rootCertificateIssueDto.commonName())
                                .organizationName(rootCertificateIssueDto.organizationName())
                                .organizationalUnitName(rootCertificateIssueDto.organizationalUnit())
                                .localityName(rootCertificateIssueDto.localityName())
                                .stateOrProvinceName(rootCertificateIssueDto.stateOrProvinceName())
                                .countryName(rootCertificateIssueDto.countryName())
                                .build();
    }

    private String toPem(Object object) {
        try (StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(object);
            pemWriter.flush();

            return writer.toString();
        } catch (Exception e) {
            throw new CaException("PEM 변환에 실패했습니다.", e);
        }
    }
}
