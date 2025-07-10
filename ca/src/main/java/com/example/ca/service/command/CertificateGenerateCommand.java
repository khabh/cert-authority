package com.example.ca.service.command;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import org.bouncycastle.asn1.x500.X500Name;

public record CertificateGenerateCommand(
    X500Name issuer,
    X500Name subject,
    PublicKey subjectPublicKey,
    PrivateKey issuerPrivateKey,
    int validityDays) {

    public CertificateGenerateCommand(
        X500Name issuer,
        X500Name subject,
        PublicKey subjectPublicKey,
        PrivateKey issuerPrivateKey,
        int validityDays) {
        this.issuer = Objects.requireNonNull(issuer);
        this.subject = Objects.requireNonNull(subject);
        this.subjectPublicKey = Objects.requireNonNull(subjectPublicKey);
        this.issuerPrivateKey = Objects.requireNonNull(issuerPrivateKey);
        this.validityDays = validityDays;
    }

    public static CertificateGenerateCommand ofSelfSign(X500Name issuer, KeyPair keyPair, int validityDays) {
        return new CertificateGenerateCommand(issuer, issuer, keyPair.getPublic(), keyPair.getPrivate(), validityDays);
    }
}
