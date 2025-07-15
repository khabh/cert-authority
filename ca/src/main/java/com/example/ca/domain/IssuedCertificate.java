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
import java.math.BigInteger;
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
    private BigInteger serial;

    @NotNull
    @Enumerated(EnumType.STRING)
    private CertificateStatus status;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY)
    private CertificationAuthority issuer;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoked_reason")
    private RevocationReason revokedReason;

    private LocalDateTime revokedAt;

    public IssuedCertificate(BigInteger serial, CertificationAuthority issuer) {
        this.serial = serial;
        this.issuer = issuer;
        this.status = CertificateStatus.GOOD;
    }

    public void revoke(RevocationReason revokedReason) {
        if (this.status == CertificateStatus.REVOKED) {
            throw new CaException("이미 폐기된 인증서입니다.");
        }
        this.status = CertificateStatus.REVOKED;
        this.revokedReason = revokedReason;
        this.revokedAt = LocalDateTime.now();
    }
}
