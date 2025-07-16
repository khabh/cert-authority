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
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificationAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "alias")
    private String alias;

    @Column(name = "serial")
    private String serial;

    @NotNull
    @Column(name = "dn", nullable = false, unique = true)
    @Convert(converter = DistinguishedNameConverter.class)
    private DistinguishedName distinguishedName;

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
        String serial,
        CertificationAuthority issuer,
        String certificate) {
        return new CertificationAuthority(null, alias, serial, distinguishedName, issuer, certificate, CaStatus.ACTIVE);
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

    public void inactive() {
        this.status = CaStatus.INACTIVE;
    }

    public boolean isInactive() {
        return this.status == CaStatus.INACTIVE;
    }

    public void renew(String alias, String certificate, String serial) {
        this.alias = alias;
        this.certificate = certificate;
        this.status = CaStatus.ACTIVE;
        this.serial = serial;
    }

    public void active(String alias, String certificate, String serial) {
        this.alias = alias;
        this.certificate = certificate;
        this.serial = serial;
        this.status = CaStatus.ACTIVE;
    }
}
