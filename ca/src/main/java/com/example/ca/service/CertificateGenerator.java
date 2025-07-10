package com.example.ca.service;

import com.example.ca.exception.CaException;
import com.example.ca.service.command.CertificateGenerateCommand;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CertificateGenerator {

    private final Clock clock;
    private final JcaContentSignerBuilder contentSignerBuilder;
    private final JcaX509CertificateConverter certificateConverter;

    public X509Certificate generateCertificate(CertificateGenerateCommand command) {
        Instant now = Instant.now(clock);
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(command.getValidityDays(), ChronoUnit.DAYS));
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            command.getIssuer(),
            serial,
            notBefore,
            notAfter,
            command.getSubject(),
            command.getSubjectPublicKey()
        );

        ContentSigner signer = createSigner(command.getIssuerPrivateKey());
        X509CertificateHolder certHolder = certBuilder.build(signer);

        return generateCertificate(certHolder);
    }

    private ContentSigner createSigner(PrivateKey issuerSecretKey) {
        try {
            return contentSignerBuilder.build(issuerSecretKey);
        } catch (OperatorCreationException e) {
            throw new CaException("인증서 서명자 생성에 실패했습니다.");
        }
    }

    private X509Certificate generateCertificate(X509CertificateHolder certHolder) {
        try {
            return certificateConverter.getCertificate(certHolder);
        } catch (CertificateException e) {
            throw new CaException("X.509 인증서 변환에 실패했습니다.");
        }
    }
}