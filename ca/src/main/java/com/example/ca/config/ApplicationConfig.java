package com.example.ca.config;

import jakarta.annotation.PostConstruct;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.time.Clock;
import java.util.Objects;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import sun.security.pkcs11.SunPKCS11;

@Configuration
public class ApplicationConfig {

    private final Provider bouncyCastleProvider = new BouncyCastleProvider();

    @PostConstruct
    public void registerProviders() {
        Security.addProvider(bouncyCastleProvider);
    }

    @Bean
    public Clock clock() {
        return Clock.systemDefaultZone();
    }

    @Bean
    public Provider provider() {
        String configPath = Objects.requireNonNull(getClass().getClassLoader().getResource("pkcs11.cfg")).getPath();
        Provider p11 = new SunPKCS11().configure(configPath);
        Security.addProvider(p11);

        return p11;
    }

    @Bean
    public JcaContentSignerBuilder contentSignerBuilder(Provider p11) {
        return new JcaContentSignerBuilder("SHA256WithRSAEncryption")
            .setProvider(p11);
    }

    @Bean
    public JcaX509CertificateConverter certificateConverter() {
        return new JcaX509CertificateConverter()
            .setProvider(bouncyCastleProvider);
    }

    @Bean
    public JcaContentVerifierProviderBuilder contentVerifierProvider() {
        return new JcaContentVerifierProviderBuilder().setProvider(bouncyCastleProvider);
    }

    @Bean
    public JcaPEMKeyConverter pemKeyConverter() {
        return new JcaPEMKeyConverter().setProvider(bouncyCastleProvider);
    }

    @Bean
    public KeyPairGenerator keyPairGenerator(Provider p11) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", p11);
            keyPairGenerator.initialize(2048);

            return keyPairGenerator;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Bean
    public KeyStore keyStore(Provider p11) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS11", p11);
            ks.load(null, "userpin".toCharArray());

            return ks;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
