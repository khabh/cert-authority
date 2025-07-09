package com.example.ca.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.ca.exception.CaException;
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
}