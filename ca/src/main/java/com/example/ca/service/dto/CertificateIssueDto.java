package com.example.ca.service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CertificateIssueDto(
    @NotNull
    Long certificateAuthorityId,

    int validityDays,

    @NotBlank
    String csr
) {
}
