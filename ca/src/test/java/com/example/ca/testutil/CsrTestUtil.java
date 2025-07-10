package com.example.ca.testutil;


import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

public class CsrTestUtil {

    public static GeneratedCsr generateCsr(String dn) {
        KeyPair keyPair = KeyPairFactory.generate();
        return generateCsr(dn, keyPair.getPrivate(), keyPair.getPublic());
    }

    public static GeneratedCsr generateCsr(String dn, PrivateKey privateKey, PublicKey publicKey) {
        X500Name subject = new X500Name(dn);

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        PKCS10CertificationRequestBuilder p10Builder = new PKCS10CertificationRequestBuilder(subject, subjectPublicKeyInfo);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");

        ContentSigner signer;
        try {
            signer = csBuilder.build(privateKey);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }

        PKCS10CertificationRequest csr = p10Builder.build(signer);

        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(csr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        String csrPem = writer.toString();

        return new GeneratedCsr(csr, csrPem);
    }
}