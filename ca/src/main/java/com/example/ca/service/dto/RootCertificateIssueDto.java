package com.example.ca.service.dto;

import jakarta.validation.constraints.NotBlank;

public record RootCertificateIssueDto(

    @NotBlank
    String commonName,

    String organizationName,

    String organizationalUnit,

    String localityName,

    String stateOrProvinceName,

    @NotBlank
    String countryName
) {
}