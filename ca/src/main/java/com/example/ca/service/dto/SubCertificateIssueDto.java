package com.example.ca.service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SubCertificateIssueDto(

    @NotNull
    Long caId,

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