package com.example.ca.service;

import com.example.ca.domain.CertificateStatus;
import com.example.ca.domain.IssuedCertificate;
import com.example.ca.domain.repository.IssuedCertificateRepository;
import com.example.ca.exception.CaException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class OcspService {

    private final IssuedCertificateRepository issuedCertificateRepository;

    public CertificateStatus checkCertificateStatus(String serial) {
        if (serial == null || serial.isBlank()) {
            throw new CaException("일련번호를 입력해주세요.");
        }

        return issuedCertificateRepository.findBySerial(serial)
                                          .map(IssuedCertificate::getStatus)
                                          .orElse(CertificateStatus.UNKNOWN);
    }
}
