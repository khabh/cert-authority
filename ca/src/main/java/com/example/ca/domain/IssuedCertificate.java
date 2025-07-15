package com.example.ca.domain;

import com.example.ca.exception.CaException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Table(name = "certificate")
@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class IssuedCertificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Column(name = "serial", unique = true, nullable = false)
    private String serial;

    @NotNull
    @Enumerated(EnumType.STRING)
    private CertificateStatus status;

    @ManyToOne(fetch = FetchType.LAZY)
    private CertificationAuthority issuer;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoked_reason")
    private RevocationReason revokedReason;

    private LocalDateTime revokedAt;

    public IssuedCertificate(String serial, CertificationAuthority issuer) {
        this.serial = serial;
        this.issuer = issuer;
        this.status = CertificateStatus.GOOD;
    }

    public void revoke(RevocationReason revokedReason) {
        if (status == CertificateStatus.REVOKED) {
            throw new CaException("Revoked revoked certificate");
        }
        this.status = CertificateStatus.REVOKED;
        this.revokedReason = revokedReason;
        this.revokedAt = LocalDateTime.now();
    }

    public void revokedByIssuer(RevocationReason reason) {
        if (reason == RevocationReason.KEY_COMPROMISE) {
            this.revokedReason = RevocationReason.KEY_COMPROMISE;
        } else {
            this.revokedReason = RevocationReason.CA_COMPROMISE;
        }
        this.status = CertificateStatus.REVOKED;
        this.revokedAt = LocalDateTime.now();
    }

    public void suspend() {
        if (status == CertificateStatus.REVOKED) {
            return;
        }
        this.status = CertificateStatus.SUSPENDED;
    }

    public boolean hasToRegenerateKey() {
        return revokedReason.isRegenerateKey();
    }

    public void resume() {
        if (status != CertificateStatus.SUSPENDED) {
            throw new CaException("Certificate is already resumed");
        }
        this.status = CertificateStatus.GOOD;
    }
}
