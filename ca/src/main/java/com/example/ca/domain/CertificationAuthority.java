package com.example.ca.domain;

import com.example.ca.domain.converter.DistinguishedNameConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

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

    public CertificationAuthority(DistinguishedName distinguishedName, String secretKey) {
        this(null, distinguishedName, secretKey);
    }
}
