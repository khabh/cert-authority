package com.example.ca.service;

import com.example.ca.exception.CaException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CertificateGenerator {

    public X509Certificate generateCertificate(
        X500Name issuer,
        X500Name subject,
        KeyPair keyPair,
        int validityDays
    ) {
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(validityDays, ChronoUnit.DAYS));
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            subject,
            keyPair.getPublic()
        );

        ContentSigner signer = createSigner(keyPair);
        X509CertificateHolder certHolder = certBuilder.build(signer);

        return generateCertificate(certHolder);
    }

    private ContentSigner createSigner(KeyPair keyPair) {
        try {
            return new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new CaException("인증서 서명자 생성에 실패했습니다.");
        }
    }

    private X509Certificate generateCertificate(X509CertificateHolder certHolder) {
        try {
            return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(certHolder);
        } catch (CertificateException e) {
            throw new CaException("X.509 인증서 변환에 실패했습니다.");
        }
    }
}