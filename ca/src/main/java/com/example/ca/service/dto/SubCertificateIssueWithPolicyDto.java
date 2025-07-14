package com.example.ca.service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SubCertificateIssueWithPolicyDto(
    @NotNull
    Long policyId,

    @NotBlank
    String commonName,

    String localityName,

    String stateOrProvinceName
) {
}
