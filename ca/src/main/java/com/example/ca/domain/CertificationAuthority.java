package com.example.ca.domain;

import com.example.ca.domain.converter.DistinguishedNameConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.NotNull;
import java.math.BigInteger;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificationAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alias")
    private String alias;

    @Column(name = "serial")
    private BigInteger serial;

    @NotNull
    @Column(name = "dn", nullable = false, unique = true)
    @Convert(converter = DistinguishedNameConverter.class)
    private DistinguishedName distinguishedName;

    @Column(name = "sk", length = 4000)
    private String secretKey;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private CertificationAuthority issuer;

    @Column(name = "certificate", nullable = false, length = 4000)
    private String certificate;

    @Enumerated(EnumType.STRING)
    private CaStatus status;

    public static CertificationAuthority withAlias(
        DistinguishedName distinguishedName,
        String alias,
        BigInteger serial,
        CertificationAuthority issuer,
        String certificate) {
        return new CertificationAuthority(null, alias, serial, distinguishedName, null, issuer, certificate, CaStatus.ACTIVE);
    }

    public CertificationAuthority(DistinguishedName distinguishedName, String secretKey, String certificate) {
        this(null, null, null, distinguishedName, secretKey, null, certificate, CaStatus.ACTIVE);
    }


    public X500Name getX500Name() {
        return distinguishedName.toX500Name();
    }

    public CaType getType() {
        if (issuer == null) {
            return CaType.ROOT;
        }
        return CaType.SUB;
    }

    public boolean isRoot() {
        return getType() == CaType.ROOT;
    }

    public boolean isSub() {
        return getType() == CaType.SUB;
    }

    public String getCommonName() {
        return distinguishedName.getCommonName();
    }

    public String getRawName() {
        return distinguishedName.toRawName();
    }

    public Long getIssuerId() {
        if (issuer == null) {
            return null;
        }
        return issuer.getId();
    }
}
