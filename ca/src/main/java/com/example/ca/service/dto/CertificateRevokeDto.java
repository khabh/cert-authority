package com.example.ca.service.dto;

import com.example.ca.domain.RevocationReason;
import jakarta.validation.constraints.NotNull;

public record CertificateRevokeDto(
    @NotNull
    String serial,

    @NotNull
    RevocationReason reason
) {
}
