package com.example.ca.service.command;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import lombok.Builder;
import lombok.Getter;
import org.bouncycastle.asn1.x500.X500Name;

@Getter
public class CertificateGenerateCommand {

    private final X500Name issuer;
    private final X500Name subject;
    private final PublicKey subjectPublicKey;
    private final PrivateKey issuerPrivateKey;
    private final int validityDays;

    @Builder
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
}
