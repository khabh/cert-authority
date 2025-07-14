package com.example.ca.service;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.Policy;
import com.example.ca.domain.repository.CertificateAuthorityRepository;
import com.example.ca.domain.repository.PolicyRepository;
import com.example.ca.service.dto.PolicyCreateDto;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class PolicyService {

    private final CertificateAuthorityRepository certificateAuthorityRepository;
    private final PolicyRepository policyRepository;

    @Transactional
    public void createPolicy(PolicyCreateDto policyCreateDto) {
        CertificationAuthority certificationAuthority = certificateAuthorityRepository.findById(policyCreateDto.issuerId())
                                                                                      .orElseThrow();
        Policy policy = new Policy(
            policyCreateDto.policyName(),
            certificationAuthority,
            policyCreateDto.organizationName(),
            policyCreateDto.organizationalUnitName(),
            policyCreateDto.countryName());

        policyRepository.save(policy);
    }

    public List<Policy> getPolicies() {
        return policyRepository.findAll();
    }
}
