package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.CertificationAuthorityDto;
import com.example.ca.service.dto.CertificationAuthorityTreeDto;
import com.example.ca.service.dto.CertificationAuthorityViewDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class CertificateUiController {

    private final CertificateService certificateService;

    @GetMapping("/")
    public String redirectToRootCa() {
        return "redirect:/dashboard";
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

    @PostMapping("/certificates/root")
    public String issueRootCaCert(@Valid RootCertificateIssueDto dto, Model model) {
        CertificateDto certificateDto = certificateService.issueRootCertificate(dto);
        model.addAttribute("certificate", certificateDto.certificate());
        return "fragments/certificate :: result";
    }

    @PostMapping("/certificates/sub")
    public String issueSubCaCert(@Valid SubCertificateIssueDto dto, Model model) {
        CertificateDto certificateDto = certificateService.issueSubCertificate(dto);
        model.addAttribute("certificate", certificateDto.certificate());
        return "fragments/certificate :: result";
    }

    @GetMapping("/dashboard")
    public String viewCaTree(Model model) {
        List<CertificationAuthorityTreeDto> tree = certificateService.getCertificationAuthorityTree();
        model.addAttribute("caTree", tree);
        return "dashboard";
    }

    @GetMapping("/ca/{id}")
    public String viewCa(@PathVariable Long id, Model model) {
        CertificationAuthorityViewDto certificationAuthorityViewDto = certificateService.getCertificationAuthority(id);
        model.addAttribute("ca", certificationAuthorityViewDto);
        return "ca";
    }

    @GetMapping("/certificates/sub/create")
    public String showSubCaForm(@RequestParam("issuerId") Long issuerId, Model model) {
        model.addAttribute("issuerId", issuerId);
        return "sub-ca";
    }

    @GetMapping("/certificates/leaf/create")
    public String showLeafCaForm(@RequestParam("issuerId") Long issuerId, Model model) {
        model.addAttribute("issuerId", issuerId);
        return "leaf-ca";
    }

    @PostMapping("/certificates")
    public String issueCertificate(@Valid CertificateIssueDto certificateIssueDto, Model model) {
        CertificateDto certificateDto = certificateService.issueCertificate(certificateIssueDto);
        model.addAttribute("certificate", certificateDto.certificate());
        return "fragments/certificate :: result";
    }
}
