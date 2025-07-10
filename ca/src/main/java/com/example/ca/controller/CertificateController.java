package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/certificates/root")
    public CertificateDto issueRootCertificate(@Valid @RequestBody RootCertificateIssueDto rootCertificateIssueDto) {
        return certificateService.issueRootCertificate(rootCertificateIssueDto);
    }

    @PostMapping("/certificates")
    public CertificateDto issueCertificate(@Valid @RequestBody CertificateIssueDto certificateIssueDto) {
        return certificateService.issueCertificate(certificateIssueDto);
    }

    @PostMapping("/certificates/sub")
    public CertificateDto issueSubCertificate(@Valid @RequestBody SubCertificateIssueDto subCertificateIssueDto) {
        return certificateService.issueSubCertificate(subCertificateIssueDto);
    }
}
