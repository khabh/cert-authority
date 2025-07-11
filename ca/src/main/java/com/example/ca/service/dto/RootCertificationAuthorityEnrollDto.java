package com.example.ca.service.dto;

import jakarta.validation.constraints.NotBlank;

public record RootCertificationAuthorityEnrollDto(

    @NotBlank
    String certificate,

    @NotBlank
    String privateKey
) {
}
