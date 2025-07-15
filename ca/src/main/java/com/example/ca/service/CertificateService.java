package com.example.ca.service;

import com.example.ca.domain.CertificateStatus;
import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import com.example.ca.domain.IssuedCertificate;
import com.example.ca.domain.Policy;
import com.example.ca.domain.RevocationReason;
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
import java.util.Arrays;
import java.util.Collection;
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
        findActiveIssuerChain(ca);
        CertificateGenerateCommand command = createCommand(certificateIssueDto, ca, csr);
        X509Certificate cert = certificateGenerator.generateCertificate(command);
        String certPem = PemUtil.toPem(cert);
        issuedCertificateRepository.save(new IssuedCertificate(cert.getSerialNumber().toString(16).toUpperCase(), ca));
        return new CertificateDto(certPem, cert.getSerialNumber().toString(16).toUpperCase());
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
        CertificationAuthority certificationAuthority = CertificationAuthority.withAlias(distinguishedName, alias, certificate.getSerialNumber()
                                                                                                                              .toString(16)
                                                                                                                              .toUpperCase(), null, certificatePem);
        certificateAuthorityRepository.save(certificationAuthority);
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber()
                                                                          .toString(16)
                                                                          .toUpperCase(), null));
        return new CertificateDto(certificatePem, certificate.getSerialNumber().toString(16).toUpperCase());
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
        CertificationAuthority subCa = CertificationAuthority.withAlias(subjectDn, alias, certificate.getSerialNumber()
                                                                                                     .toString(16)
                                                                                                     .toUpperCase(), ca, certificatePem);
        certificateAuthorityRepository.save(subCa);
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber()
                                                                          .toString(16)
                                                                          .toUpperCase(), ca));

        return new CertificateDto(certificatePem, certificate.getSerialNumber().toString(16).toUpperCase());
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
        CertificationAuthority certificationAuthority = CertificationAuthority.withAlias(distinguishedName, alias, certificate.getSerialNumber()
                                                                                                                              .toString(16)
                                                                                                                              .toUpperCase(), null, PemUtil.toPem(certificate));
        certificateAuthorityRepository.save(certificationAuthority);
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber()
                                                                          .toString(16)
                                                                          .toUpperCase(), null));

        return certificationAuthority.getId();
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
        IssuedCertificate issuedCertificate = issuedCertificateRepository.findBySerial(dto.serial()).orElseThrow();

        RevocationReason reason = dto.reason();
        issuedCertificate.revoke(reason);
        certificateAuthorityRepository.findBySerial(dto.serial())
                                      .ifPresent(certificationAuthority -> revokeCertificateAuthority(certificationAuthority, reason));
    }

    @Transactional
    public void renewCaCertificate(Long caId) {
        CertificationAuthority ca = certificateAuthorityRepository.findById(caId).orElseThrow();
        if (!ca.isInactive()) {
            throw new CaException("INACTIVE 상태의 CA만 재발급할 수 있습니다.");
        }
        IssuedCertificate issuedCertificate = issuedCertificateRepository.findBySerial(ca.getSerial())
                                                                         .orElseThrow();

        if (issuedCertificate.hasToRegenerateKey()) {
            renewCertificateAuthorityByKey(ca);
            return;
        }

        if (ca.isRoot()) {
            X509Certificate certificate = CertificateUtil.getCertificate(ca.getCertificate());
            KeyPair keyPair = new KeyPair(certificate.getPublicKey(), keyStoreManager.getPrivateKey(ca.getAlias()));
            X509Certificate renew = certificateGenerator.generateCertificate(CertificateGenerateCommand.ofSelfSign(
                ca.getX500Name(),
                keyPair,
                365
            ));
            ca.active(PemUtil.toPem(renew), renew.getSerialNumber().toString(16).toUpperCase());
            issuedCertificateRepository.save(new IssuedCertificate(renew.getSerialNumber()
                                                                        .toString(16)
                                                                        .toUpperCase(), null));
            renewCertificateAuthorityWithoutKey(ca, new Certificate[]{});
        } else {
            CertificationAuthority issuer = certificateAuthorityRepository.findById(ca.getIssuerId()).orElseThrow();
            X509Certificate certificate = CertificateUtil.getCertificate(ca.getCertificate());
            X509Certificate renew = certificateGenerator.generateCertificate(new CertificateGenerateCommand(
                issuer.getX500Name(),
                ca.getX500Name(),
                certificate.getPublicKey(),
                keyStoreManager.getPrivateKey(issuer.getAlias()),
                365
            ));
            ca.active(PemUtil.toPem(renew), renew.getSerialNumber().toString(16).toUpperCase());
            issuedCertificateRepository.save(new IssuedCertificate(renew.getSerialNumber()
                                                                        .toString(16)
                                                                        .toUpperCase(), issuer));

            renewCertificateAuthorityWithoutKey(ca, findActiveIssuerChain(ca).toArray(Certificate[]::new));
        }
    }

    private void renewCertificateAuthorityWithoutKey(CertificationAuthority ca, Certificate[] certificates) {
        Certificate[] currentChain = Stream.concat(
            Stream.of(CertificateUtil.getCertificate(ca.getCertificate())),
            Arrays.stream(certificates)
        ).toArray(Certificate[]::new);

        issuedCertificateRepository.findAllByIssuer(ca)
                                   .stream()
                                   .filter(issuedCertificate -> issuedCertificate.getStatus() != CertificateStatus.REVOKED)
                                   .forEach(IssuedCertificate::resume);

        String alias = keyStoreManager.setKeyEntry(keyStoreManager.getPrivateKey(ca.getAlias()), currentChain, ca.getType());
        keyStoreManager.removeKeyEntry(ca.getAlias());
        ca.setAlias(alias);
        certificateAuthorityRepository.findAllByIssuer(ca)
                                      .forEach(sub -> renewCertificateAuthorityWithoutKey(sub, currentChain));
    }

    private void renewCertificateAuthorityByKey(CertificationAuthority ca) {
        if (ca.isRoot()) {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            X509Certificate certificate = certificateGenerator.generateCertificate(CertificateGenerateCommand.ofSelfSign(
                ca.getX500Name(),
                keyPair,
                365
            ));
            String alias = keyStoreManager.setRootKeyEntry(keyPair.getPrivate(), certificate);
            ca.renew(alias, PemUtil.toPem(certificate), certificate.getSerialNumber().toString(16).toUpperCase());
            issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber()
                                                                              .toString(16)
                                                                              .toUpperCase(), null));
            certificateAuthorityRepository.findAllByIssuer(ca)
                                          .forEach(sub -> renewCertificateAuthorityByKey(sub, new Certificate[]{certificate}));
        } else {
            renewCertificateAuthorityByKey(ca, findActiveIssuerChain(ca).toArray(Certificate[]::new));
        }
    }

    private void renewCertificateAuthorityByKey(CertificationAuthority ca, Certificate[] certificates) {
        PublicKey publicKey = CertificateUtil.getCertificate(ca.getCertificate()).getPublicKey();
        CertificationAuthority issuer = ca.getIssuer();
        X509Certificate certificate = certificateGenerator.generateCertificate(new CertificateGenerateCommand(
            issuer.getX500Name(),
            ca.getX500Name(),
            publicKey,
            keyStoreManager.getPrivateKey(issuer.getAlias()),
            365
        ));

        Certificate[] currentChain = Stream.concat(
            Stream.of(certificate),
            Arrays.stream(certificates)
        ).toArray(Certificate[]::new);
        ca.renew(PemUtil.toPem(certificate), certificate.getSerialNumber().toString(16).toUpperCase());
        issuedCertificateRepository.save(new IssuedCertificate(certificate.getSerialNumber()
                                                                          .toString(16)
                                                                          .toUpperCase(), issuer));
        certificateAuthorityRepository.findAllByIssuer(ca)
                                      .forEach(sub -> renewCertificateAuthorityByKey(sub, currentChain));
    }

    private void revokeCertificateAuthority(CertificationAuthority ca, RevocationReason reason) {
        ca.inactive();
        List<CertificationAuthority> subAuthorities = certificateAuthorityRepository.findAllDescendantsByIssuerId(ca.getId());
        List<IssuedCertificate> issuedCertificates = subAuthorities.stream()
                                                                   .map(issuedCertificateRepository::findAllByIssuer)
                                                                   .flatMap(Collection::stream)
                                                                   .collect(Collectors.toList());
        issuedCertificates.addAll(issuedCertificateRepository.findAllByIssuer(ca));

        if (reason.isRegenerateKey()) {
            issuedCertificates.forEach(issuedCertificate -> issuedCertificate.revokedByIssuer(reason));
        } else {
            issuedCertificates.forEach(IssuedCertificate::suspend);
        }
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
