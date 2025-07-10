package com.example.ca.service.dto;

import com.example.ca.domain.CertificationAuthority;

public record CertificationAuthorityDto(
    Long id,
    String distinguishedName
) {

    public static CertificationAuthorityDto of(CertificationAuthority certificationAuthority) {
        return new CertificationAuthorityDto(
            certificationAuthority.getId(),
            certificationAuthority.getX500Name().toString()
        );
    }
}
