package com.example.ca.domain;

import com.example.ca.domain.converter.DistinguishedNameConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class CertificationAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Column(name = "dn", nullable = false, unique = true)
    @Convert(converter = DistinguishedNameConverter.class)
    private DistinguishedName distinguishedName;

    @NotBlank
    @Column(name = "sk", nullable = false, length = 4000)
    private String secretKey;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private CertificationAuthority issuer;

    @Column(name = "certificate", nullable = false, length = 4000)
    private String certificate;

    public CertificationAuthority(DistinguishedName distinguishedName, String secretKey, String certificate) {
        this(null, distinguishedName, secretKey, null, certificate);
    }

    public CertificationAuthority(
        DistinguishedName distinguishedName,
        String secretKey,
        CertificationAuthority issuer,
        String certificate) {
        this(null, distinguishedName, secretKey, issuer, certificate);
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
