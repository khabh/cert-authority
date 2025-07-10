package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.CertificationAuthorityDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class CertificateUiController {

    private final CertificateService certificateService;

    @GetMapping("/")
    public String redirectToRootCa() {
        return "redirect:/certificates/root/create";
    }

    @GetMapping("/certificates/root/create")
    public String showRootCaForm() {
        return "root-ca";
    }

    @GetMapping("/certificates/create")
    public String showCertificateIssueForm(Model model) {
        List<CertificationAuthorityDto> cas = certificateService.findAllCertificationAuthorities();
        model.addAttribute("cas", cas);
        return "issue-certificate";
    }

    @PostMapping("/certificates")
    public String issueLeafCert(@Valid CertificateIssueDto dto, Model model) {
        CertificateDto certificateDto = certificateService.issueCertificate(dto);
        model.addAttribute("certificate", certificateDto.certificate());
        return "fragments/certificate :: result";
    }

    @PostMapping("/certificates/root")
    public String issueRootCaCert(@Valid RootCertificateIssueDto dto, Model model) {
        CertificateDto certificateDto = certificateService.issueRootCertificate(dto);
        model.addAttribute("certificate", certificateDto.certificate());
        return "fragments/certificate :: result";
    }
}
