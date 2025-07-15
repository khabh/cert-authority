package com.example.ca.domain.repository;

import com.example.ca.domain.CertificationAuthority;
import com.example.ca.domain.IssuedCertificate;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IssuedCertificateRepository extends JpaRepository<IssuedCertificate, Long> {

    Optional<IssuedCertificate> findBySerial(BigInteger serial);

    List<IssuedCertificate> findAllByIssuer(CertificationAuthority issuer);
}
