package com.example.ca.testutil;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class PemUtils {

    public static X509Certificate parseCertificateFromPem(String pem) {
        try {
            String base64 = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");

            byte[] der = Base64.getDecoder().decode(base64);

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("PEM 인증서 파싱에 실패했습니다.", e);
        }
    }
}
