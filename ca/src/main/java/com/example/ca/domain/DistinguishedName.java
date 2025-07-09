package com.example.ca.domain;

import com.example.ca.exception.CaException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class DistinguishedName {

    private static final Set<String> COUNTRIES = Arrays.stream(Locale.getISOCountries())
                                                       .collect(Collectors.toUnmodifiableSet());

    private String commonName;

    private String organizationName;

    private String organizationalUnitName;

    private String localityName;

    private String stateOrProvinceName;

    private String countryName;

    public DistinguishedName(
        String commonName,
        String organizationName,
        String organizationalUnitName,
        String localityName,
        String stateOrProvinceName,
        String countryName) {
        String upperCountryName = countryName.toUpperCase(Locale.ROOT);
        validateCountryName(upperCountryName);

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

    public static DistinguishedName from(String rawName) {
        X500Name x500Name = new X500Name(rawName);

        Map<ASN1ObjectIdentifier, String> rdnMap = Arrays.stream(x500Name.getRDNs())
                                                         .filter(rdn -> rdn.getFirst() != null)
                                                         .collect(Collectors.toMap(
                                                             rdn -> rdn.getFirst().getType(),
                                                             rdn -> ((ASN1String) rdn.getFirst().getValue()).getString()
                                                         ));

        return DistinguishedName.builder()
                                .commonName(rdnMap.get(BCStyle.CN))
                                .organizationName(rdnMap.get(BCStyle.O))
                                .organizationalUnitName(rdnMap.get(BCStyle.OU))
                                .localityName(rdnMap.get(BCStyle.L))
                                .stateOrProvinceName(rdnMap.get(BCStyle.ST))
                                .countryName(rdnMap.get(BCStyle.C))
                                .build();
    }

    public String toRawName() {
        return toX500Name().toString();
    }

    public X500Name toX500Name() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        Stream.of(
                  rdnIfNotBlank(BCStyle.C, countryName),
                  rdnIfNotBlank(BCStyle.ST, stateOrProvinceName),
                  rdnIfNotBlank(BCStyle.L, localityName),
                  rdnIfNotBlank(BCStyle.O, organizationName),
                  rdnIfNotBlank(BCStyle.OU, organizationalUnitName),
                  rdnIfNotBlank(BCStyle.CN, commonName)
              ).flatMap(Optional::stream)
              .forEach(rdn -> builder.addRDN(rdn.getKey(), rdn.getValue()));

        return builder.build();
    }


    private Optional<Map.Entry<ASN1ObjectIdentifier, String>> rdnIfNotBlank(ASN1ObjectIdentifier key, String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(Map.entry(key, value));
    }
}
