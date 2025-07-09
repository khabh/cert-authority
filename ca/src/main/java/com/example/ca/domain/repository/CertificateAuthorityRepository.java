package com.example.ca.domain.repository;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateAuthorityRepository extends JpaRepository<CertificationAuthority, Long> {
    boolean existsByDistinguishedName(DistinguishedName distinguishedName);
}
