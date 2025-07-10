package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class CertificateUiController {

    private final CertificateService certificateService;

    @GetMapping("/certificates/root/create")
    public String showRootCaForm() {
        return "root-ca";
    }

    @PostMapping("/certificates/root")
    public String issueRootCaCert(@Valid RootCertificateIssueDto dto, Model model) {
        CertificateDto certificateDto = certificateService.issueRootCertificate(dto);
        model.addAttribute("certificate", certificateDto.certificate());
        return "fragments/certificate :: result";
    }
}
