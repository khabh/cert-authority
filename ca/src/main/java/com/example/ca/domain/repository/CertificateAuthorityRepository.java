package com.example.ca.domain.repository;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.DistinguishedName;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateAuthorityRepository extends JpaRepository<CertificationAuthority, Long> {

    boolean existsByDistinguishedName(DistinguishedName distinguishedName);

    Optional<CertificationAuthority> findBySerial(String serial);

    @Query(
        value = """
                WITH RECURSIVE ca_hierarchy(id, alias, serial, dn, issuer_id, certificate, status) AS (
                  SELECT id, alias, serial, dn, issuer_id, certificate, status
                  FROM certification_authority
                  WHERE id = :issuerId
                  UNION ALL
                  SELECT ca.id, ca.alias, ca.serial, ca.dn, ca.issuer_id, ca.certificate, ca.status
                  FROM certification_authority ca
                  JOIN ca_hierarchy parent ON ca.issuer_id = parent.id
                )
                SELECT * FROM ca_hierarchy WHERE id != :issuerId
                """, nativeQuery = true)
    List<CertificationAuthority> findAllDescendantsByIssuerId(@Param("issuerId") Long issuerId);

    List<CertificationAuthority> findAllByIssuer(CertificationAuthority ca);
}
