package com.example.ca.service;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import com.example.ca.domain.IssuedCertificate;
import com.example.ca.domain.Policy;
import com.example.ca.domain.repository.CertificateAuthorityRepository;
import com.example.ca.domain.repository.IssuedCertificateRepository;
import com.example.ca.domain.repository.PolicyRepository;
import com.example.ca.exception.CaException;
import com.example.ca.service.command.CertificateGenerateCommand;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.CertificateRevokeDto;
import com.example.ca.service.dto.CertificationAuthorityTreeDto;
import com.example.ca.service.dto.CertificationAuthorityViewDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.RootCertificationAuthorityEnrollDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import com.example.ca.service.dto.SubCertificateIssueWithPolicyDto;
import com.example.ca.util.CertificateUtil;
import com.example.ca.util.PemUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CertificateService {

    private final CertificateGenerator certificateGenerator;
    private final CsrProcessor csrProcessor;
    private final PrivateKeyParser privateKeyParser;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyStoreManager keyStoreManager;
    private final CertificateAuthorityRepository certificateAuthorityRepository;
    private final PolicyRepository policyRepository;
    private final IssuedCertificateRepository issuedCertificateRepository;

    @Transactional
    public CertificateDto issueCertificate(CertificateIssueDto certificateIssueDto) {
        PKCS10CertificationRequest csr = csrProcessor.parseValidCsr(certificateIssueDto.csr());
        CertificationAuthority ca = findCertificationAuthority(certificateIssueDto.certificateAuthorityId());
        CertificateGenerateCommand command = createCommand(certificateIssueDto, ca, csr);
        X509Certificate cert = certificateGenerator.generateCertificate(command);
        String certPem = PemUtil.toPem(cert);
        issuedCertificateRepository.save(new IssuedCertificate(cert.getSerialNumber(), ca));
        return new CertificateDto(certPem);
    }

    @Transactional
    public CertificateDto issueRootCertificate(RootCertificateIssueDto rootCertificateIssueDto) {
        DistinguishedName distinguishedName = dtoToDistinguishedName(rootCertificateIssueDto);
        validateCaUnique(distinguishedName);

        X500Name subject = distinguishedName.toX500Name();
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        CertificateGenerateCommand command = CertificateGenerateCommand.ofSelfSign(subject, keyPair, 365);
        X509Certificate certificate = certificateGenerator.generateCertificate(command);

        String alias = keyStoreManager.setRootKeyEntry(keyPair.getPrivate(), certificate);
        String certificatePem = PemUtil.toPem(certificate);
        CertificationAuthority certificationAuthority = CertificationAuthority.withAlias(distinguishedName, alias, certificate.getSerialNumber(), null, certificatePem);
        certificateAuthorityRepository.save(certificationAuthority);
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber(), certificationAuthority));
        return new CertificateDto(certificatePem);
    }

    @Transactional
    public CertificateDto issueSubCertificate(SubCertificateIssueDto subCertificateIssueDto) {
        DistinguishedName subjectDn = dtoToDistinguishedName(subCertificateIssueDto);
        validateCaUnique(subjectDn);
        CertificationAuthority ca = findCertificationAuthority(subCertificateIssueDto.caId());
        PrivateKey issuerPrivateKey = keyStoreManager.getPrivateKey(ca.getAlias());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        CertificateGenerateCommand command = new CertificateGenerateCommand(
            ca.getX500Name(),
            subjectDn.toX500Name(),
            keyPair.getPublic(),
            issuerPrivateKey,
            365
        );

        X509Certificate certificate = certificateGenerator.generateCertificate(command);
        List<Certificate> chain = findActiveIssuerChain(ca);
        chain.addFirst(certificate);

        String alias = keyStoreManager.setSubKeyEntry(keyPair.getPrivate(), chain.toArray(Certificate[]::new));
        String certificatePem = PemUtil.toPem(certificate);
        CertificationAuthority subCa = CertificationAuthority.withAlias(subjectDn, alias, certificate.getSerialNumber(), ca, certificatePem);
        certificateAuthorityRepository.save(subCa);
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber(), ca));

        return new CertificateDto(certificatePem);
    }

    private List<Certificate> findActiveIssuerChain(CertificationAuthority ca) {
        List<Certificate> chain = Stream.iterate(ca, Objects::nonNull, CertificationAuthority::getIssuer)
                                        .map(certificationAuthority -> {
                                            if (certificationAuthority.isInactive()) {
                                                throw new CaException("상위 CA가 비활성화되어 발급이 제한됩니다.");
                                            }
                                            return CertificateUtil.getCertificate(certificationAuthority.getCertificate());
                                        })
                                        .collect(Collectors.toCollection(ArrayList::new));
        Collections.reverse(chain);

        return chain;
    }

    public List<CertificationAuthorityTreeDto> getCertificationAuthorityTree() {
        List<CertificationAuthority> certificationAuthorities = certificateAuthorityRepository.findAll();
        List<CertificationAuthority> rootCertificationAuthorities = certificationAuthorities.stream()
                                                                                            .filter(CertificationAuthority::isRoot)
                                                                                            .toList();
        Map<Long, List<CertificationAuthority>> subCertificationAuthorities = certificationAuthorities.stream()
                                                                                                      .filter(CertificationAuthority::isSub)
                                                                                                      .collect(Collectors.groupingBy(CertificationAuthority::getIssuerId));

        return rootCertificationAuthorities.stream()
                                           .map(ca -> CertificationAuthorityTreeDto.from(ca, subCertificationAuthorities))
                                           .toList();
    }

    @Transactional
    public Long enrollRootCertificationAuthority(RootCertificationAuthorityEnrollDto dto) {
        X509Certificate certificate = CertificateUtil.getCertificate(dto.certificate());
        PrivateKey privateKey = privateKeyParser.parsePrivateKey(dto.privateKey());

        validateRootCertificationAuthority(certificate, privateKey);
        DistinguishedName distinguishedName = DistinguishedName.from(certificate.getIssuerX500Principal().getName());
        validateCaUnique(distinguishedName);
        String alias = keyStoreManager.setRootKeyEntry(privateKey, certificate);
        CertificationAuthority certificationAuthority = CertificationAuthority.withAlias(distinguishedName, alias, certificate.getSerialNumber(), null, PemUtil.toPem(certificate));
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber(), certificationAuthority));

        return certificateAuthorityRepository.save(certificationAuthority).getId();
    }

    public List<CertificationAuthorityViewDto> getCertificationAuthorityView() {
        return certificateAuthorityRepository.findAll()
                                             .stream()
                                             .map(CertificationAuthorityViewDto::of)
                                             .toList();
    }

    public CertificationAuthorityViewDto getCertificationAuthority(Long id) {
        CertificationAuthority certificationAuthority = certificateAuthorityRepository.findById(id)
                                                                                      .orElseThrow(() -> new CaException("등록되지 않은 CA입니다."));
        return CertificationAuthorityViewDto.of(certificationAuthority);
    }

    @Transactional
    public CertificateDto issueSubCertificateWithPolicy(SubCertificateIssueWithPolicyDto dto) {
        Policy policy = policyRepository.findById(dto.policyId()).orElseThrow();
        SubCertificateIssueDto subCertificateIssueDto = new SubCertificateIssueDto(
            policy.getIssuer().getId(),
            dto.commonName(),
            policy.getOrganizationName(),
            policy.getOrganizationalUnitName(),
            dto.localityName(),
            dto.stateOrProvinceName(),
            policy.getCountryName()
        );

        return issueSubCertificate(subCertificateIssueDto);
    }

    @Transactional
    public void revokeCertificate(CertificateRevokeDto dto) {
        BigInteger serial = new BigInteger(dto.serial().replaceFirst("^0x", ""), 16);
        IssuedCertificate issuedCertificate = issuedCertificateRepository.findBySerial(serial).orElseThrow();

        issuedCertificate.revoke(dto.reason());

        certificateAuthorityRepository.findBySerial(serial)
                                      .ifPresent(CertificationAuthority::inactive);
    }

    private void validateRootCertificationAuthority(X509Certificate certificate, PrivateKey privateKey) {
        try {
            certificate.verify(certificate.getPublicKey());
            boolean isSelfIssued = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
            if (!isSelfIssued) {
                throw new CaException("셀프 사인 인증서가 아닙니다.");
            }
            certificate.checkValidity();
            validateIsPair(certificate.getPublicKey(), privateKey);
        } catch (CaException e) {
            throw e;
        } catch (Exception e) {
            throw new CaException("유효하지 않은 인증서입니다.");
        }
    }

    private void validateIsPair(PublicKey publicKey, PrivateKey privateKey) {
        try {
            byte[] testData = "test".getBytes(StandardCharsets.UTF_8);

            String algorithm = getSignatureAlgorithm(publicKey.getAlgorithm());

            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            signature.update(testData);
            byte[] signBytes = signature.sign();

            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(testData);

            if (!verifier.verify(signBytes)) {
                throw new CaException("올바르지 않은 개인키입니다.");
            }
        } catch (Exception e) {
            throw new CaException("개인키 검증에 실패했습니다.");
        }
    }

    private String getSignatureAlgorithm(String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case "RSA" -> "SHA256withRSA";
            case "DSA" -> "SHA256withDSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            default -> throw new IllegalArgumentException("Unsupported key algorithm: " + keyAlgorithm);
        };
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

        return new CertificateGenerateCommand(
            ca.getX500Name(),
            csr.getSubject(),
            subjectKey,
            keyStoreManager.getPrivateKey(ca.getAlias()),
            certificateIssueDto.validityDays()
        );
    }

    private void validateCaUnique(DistinguishedName distinguishedName) {
        if (certificateAuthorityRepository.existsByDistinguishedName(distinguishedName)) {
            throw new CaException("해당 DN으로 등록된 CA가 존재합니다.");
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

    private DistinguishedName dtoToDistinguishedName(SubCertificateIssueDto subCertificateIssueDto) {
        return DistinguishedName.builder()
                                .commonName(subCertificateIssueDto.commonName())
                                .organizationName(subCertificateIssueDto.organizationName())
                                .organizationalUnitName(subCertificateIssueDto.organizationalUnit())
                                .localityName(subCertificateIssueDto.localityName())
                                .stateOrProvinceName(subCertificateIssueDto.stateOrProvinceName())
                                .countryName(subCertificateIssueDto.countryName())
                                .build();
    }
}
