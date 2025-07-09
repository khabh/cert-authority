package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
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
}
