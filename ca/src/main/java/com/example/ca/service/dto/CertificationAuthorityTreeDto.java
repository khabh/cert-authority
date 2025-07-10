package com.example.ca.service.dto;

import com.example.ca.domain.CaType;
import com.example.ca.domain.CertificationAuthority;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public record CertificationAuthorityTreeDto(
    Long id,
    String commonName,
    CaType type,
    List<CertificationAuthorityTreeDto> children
) {

    public static CertificationAuthorityTreeDto from(
        CertificationAuthority ca,
        Map<Long, List<CertificationAuthority>> childMap
    ) {
        List<CertificationAuthority> children = childMap.getOrDefault(ca.getId(), Collections.emptyList());

        return new CertificationAuthorityTreeDto(
            ca.getId(),
            ca.getCommonName(),
            ca.getType(),
            children.stream()
                    .map(child -> CertificationAuthorityTreeDto.from(child, childMap))
                    .toList()
        );
    }
}
