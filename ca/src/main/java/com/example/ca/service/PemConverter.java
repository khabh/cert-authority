package com.example.ca.service;

import com.example.ca.exception.CaException;
import java.io.StringWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Component;

@Component
public class PemConverter {

    public String toPem(Object object) {
        try (StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(object);
            pemWriter.flush();

            return writer.toString();
        } catch (Exception e) {
            throw new CaException("PEM 변환에 실패했습니다.", e);
        }
    }
}