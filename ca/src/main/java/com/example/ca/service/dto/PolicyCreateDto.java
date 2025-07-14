package com.example.ca.service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record PolicyCreateDto(
    @NotBlank
    String policyName,

    @NotNull
    Long issuerId,

    @NotBlank
    String organizationName,

    @NotBlank
    String organizationalUnitName,

    @NotBlank
    String countryName
) {
}
