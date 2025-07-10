package com.example.ca.config;

import java.security.Provider;
import java.time.Clock;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApplicationConfig {

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }

    @Bean
    public Provider provider() {
        return new BouncyCastleProvider();
    }

    @Bean
    public JcaContentSignerBuilder contentSignerBuilder(Provider provider) {
        return new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(provider);
    }

    @Bean
    public JcaX509CertificateConverter certificateConverter(Provider provider) {
        return new JcaX509CertificateConverter()
            .setProvider(provider);
    }

    @Bean
    public JcaContentVerifierProviderBuilder contentVerifierProvider(Provider provider) {
        return new JcaContentVerifierProviderBuilder().setProvider(provider);
    }

    @Bean
    public JcaPEMKeyConverter pemKeyConverter(Provider provider) {
        return new JcaPEMKeyConverter().setProvider(provider);
    }
}
