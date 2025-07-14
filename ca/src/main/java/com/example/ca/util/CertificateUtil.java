package com.example.ca.util;

import com.example.ca.exception.CaException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.util.encoders.Base64;

public class CertificateUtil {

    private static final CertificateFactory CERTIFICATE_FACTORY;

    static {
        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate getCertificate(String certPem) {
        String base64Cert = certPem
            .replaceAll("-----BEGIN CERTIFICATE-----", "")
            .replaceAll("-----END CERTIFICATE-----", "")
            .replaceAll("\\s", "");

        byte[] certBytes = Base64.decode(base64Cert);

        try {
            return (X509Certificate) CERTIFICATE_FACTORY.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            throw new CaException("인증서 변환에 실패했습니다.");
        }
    }
}
