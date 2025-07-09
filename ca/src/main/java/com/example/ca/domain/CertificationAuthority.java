package com.example.ca.domain;

import com.example.ca.domain.converter.DistinguishedNameConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class CertificationAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Convert(converter = DistinguishedNameConverter.class)
    @Column(name = "dn", nullable = false, unique = true)
    private DistinguishedName distinguishedName;

    @Column(name = "sk", nullable = false)
    private String secretKey;

    public CertificationAuthority(Long id, DistinguishedName distinguishedName, String secretKey) {
        this.id = id;
        this.distinguishedName = distinguishedName;
        this.secretKey = secretKey;
    }
}
