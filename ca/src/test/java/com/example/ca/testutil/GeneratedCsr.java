package com.example.ca.testutil;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public record GeneratedCsr(
    PKCS10CertificationRequest csr,
    String csrPem
) {
}
