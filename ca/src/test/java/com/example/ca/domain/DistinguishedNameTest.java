package com.example.ca.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.ca.exception.CaException;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DistinguishedNameTest {

    @Test
    @DisplayName("올바른 countryName이면 객체 생성 시 예외가 발생하지 않는다.")
    void new1() {
        String validCountry = "KR";

        DistinguishedName dn = new DistinguishedName(
            "Alice",
            "ExampleOrg",
            "DevUnit",
            "Seoul",
            "Seoul",
            validCountry
        );

        assertThat(dn).isNotNull();
        assertThat(dn.getCountryName()).isEqualTo(validCountry);
        assertThat(dn.getCommonName()).isEqualTo("Alice");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ZZ", "KK"})
    @DisplayName("잘못된 countryName이면 CaException이 발생한다.")
    void new2(String invalidCountry) {
        assertThatThrownBy(() -> new DistinguishedName(
            "Alice",
            "ExampleOrg",
            "DevUnit",
            "Seoul",
            "Seoul",
            invalidCountry
        )).isInstanceOf(CaException.class)
          .hasMessageContaining("Country Name " + invalidCountry + " is invalid");
    }

    @Test
    @DisplayName("from(String)으로 X500 문자열을 DistinguishedName으로 변환할 수 있다.")
    void fromRawName() {
        String rawName = "C=KR,ST=Seoul,L=Seoul,O=ExampleOrg,OU=DevUnit,CN=Alice";

        DistinguishedName parsed = DistinguishedName.from(rawName);

        assertThat(parsed.getCommonName()).isEqualTo("Alice");
        assertThat(parsed.getOrganizationName()).isEqualTo("ExampleOrg");
        assertThat(parsed.getOrganizationalUnitName()).isEqualTo("DevUnit");
        assertThat(parsed.getLocalityName()).isEqualTo("Seoul");
        assertThat(parsed.getStateOrProvinceName()).isEqualTo("Seoul");
        assertThat(parsed.getCountryName()).isEqualTo("KR");
    }

    @Test
    @DisplayName("null 또는 공백 필드는 toX500Name 변환 시 제외된다.")
    void x500NameSkipsNullOrBlankFields() {
        DistinguishedName dn = DistinguishedName.builder()
                                                .commonName("Alice")
                                                .countryName("KR")
                                                .organizationName("  ")
                                                .build();

        X500Name x500Name = dn.toX500Name();
        String x500Str = x500Name.toString();

        assertThat(x500Str).contains("CN=Alice");
        assertThat(x500Str).contains("C=KR");
        assertThat(x500Str).doesNotContain("O=");
    }
}