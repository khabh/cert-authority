package com.example.ca.service.dto;

import com.example.ca.domain.CaStatus;
import com.example.ca.domain.CertificationAuthority;

public record CertificationAuthorityViewDto(
    Long id,
    String commonName,
    String distinguishedName,
    String serialNumber,
    String certificate,
    CaStatus status
) {

    public static CertificationAuthorityViewDto of(CertificationAuthority certificationAuthority) {
        return new CertificationAuthorityViewDto(
            certificationAuthority.getId(),
            certificationAuthority.getCommonName(),
            certificationAuthority.getRawName(),
            certificationAuthority.getHexSerial(),
            certificationAuthority.getCertificate(),
            certificationAuthority.getStatus()
        );
    }
}
