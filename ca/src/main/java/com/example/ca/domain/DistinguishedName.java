package com.example.ca.domain;

import com.example.ca.exception.CaException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotBlank;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(uniqueConstraints = @UniqueConstraint(columnNames = {"cn", "o", "ou", "l", "st", "c"}))
public class DistinguishedName {

    private static final Set<String> COUNTRIES = Arrays.stream(Locale.getISOCountries())
                                                       .collect(Collectors.toUnmodifiableSet());

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(name = "cn", nullable = false)
    private String commonName;

    @Column(name = "o")
    private String organizationName;

    @Column(name = "ou")
    private String organizationalUnitName;

    @Column(name = "l")
    private String localityName;

    @Column(name = "st")
    private String stateOrProvinceName;

    @NotBlank
    @Column(name = "c", length = 2, nullable = false)
    private String countryName;

    public DistinguishedName(
        Long id,
        String commonName,
        String organizationName,
        String organizationalUnitName,
        String localityName,
        String stateOrProvinceName,
        String countryName) {
        String upperCountryName = countryName.toUpperCase(Locale.ROOT);
        validateCountryName(upperCountryName);

        this.id = id;
        this.commonName = commonName;
        this.organizationName = organizationName;
        this.organizationalUnitName = organizationalUnitName;
        this.localityName = localityName;
        this.stateOrProvinceName = stateOrProvinceName;
        this.countryName = upperCountryName;
    }

    private void validateCountryName(String countryName) {
        if (!COUNTRIES.contains(countryName)) {
            throw new CaException("Country Name " + countryName + " is invalid");
        }
    }
}
