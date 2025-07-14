package com.example.ca.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Table(name = "policy")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Policy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String name;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id", nullable = false)
    private CertificationAuthority issuer;

    @NotBlank
    @Column(name = "o", nullable = false)
    private String organizationName;

    @NotBlank
    @Column(name = "ou", nullable = false)
    private String organizationalUnitName;

    @NotBlank
    @Column(name = "c", length = 2, nullable = false)
    private String countryName;

    public Policy(
        String name,
        CertificationAuthority issuer,
        String organizationName,
        String organizationalUnitName,
        String countryName) {
        this.name = name;
        this.issuer = issuer;
        this.organizationName = organizationName;
        this.organizationalUnitName = organizationalUnitName;
        this.countryName = countryName;
    }
}
