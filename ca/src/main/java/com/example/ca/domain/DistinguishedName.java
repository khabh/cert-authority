package com.example.ca.domain;

import com.example.ca.exception.CaException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
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
        return createName(List.of(
            Map.entry(BCStyle.C, countryName),
            Map.entry(BCStyle.ST, stateOrProvinceName),
            Map.entry(BCStyle.L, localityName),
            Map.entry(BCStyle.O, organizationName),
            Map.entry(BCStyle.OU, organizationalUnitName),
            Map.entry(BCStyle.CN, commonName)
        ));
    }

    private X500Name createName(List<Map.Entry<ASN1ObjectIdentifier, String>> rdns) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        rdns.stream()
            .filter(entry -> entry.getValue() != null && !entry.getValue().isBlank())
            .forEach(entry -> builder.addRDN(entry.getKey(), entry.getValue()));

        return builder.build();
    }
}
