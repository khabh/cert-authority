package com.example.ca.service;

import com.example.ca.exception.CaException;
import java.io.StringReader;
import java.security.PublicKey;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CsrProcessor {

    private final JcaContentVerifierProviderBuilder contentVerifierProviderBuilder;

    public PKCS10CertificationRequest parseValidCsr(String csrPem) {
        PKCS10CertificationRequest csr = parseCsr(csrPem);
        validateCsr(csr);

        return csr;
    }

    private PKCS10CertificationRequest parseCsr(String pem) {
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            Object object = pemParser.readObject();
            if (object instanceof PKCS10CertificationRequest csr) {
                return csr;
            }
            throw new CaException("CSR 형식이 유효하지 않습니다.");
        } catch (Exception e) {
            throw new CaException("CSR 파싱에 실패했습니다.", e);
        }
    }

    private void validateCsr(PKCS10CertificationRequest csr) {
        try {
            JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(csr);
            PublicKey publicKey = jcaRequest.getPublicKey();

            if (!csr.isSignatureValid(contentVerifierProviderBuilder.build(publicKey))) {
                throw new CaException("CSR 서명 유효성 검증에 실패했습니다.");
            }
        } catch (Exception e) {
            throw new CaException("CSR 서명 검증 중 오류가 발생했습니다.", e);
        }
    }
}