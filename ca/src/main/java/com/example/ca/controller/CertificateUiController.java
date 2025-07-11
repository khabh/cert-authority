package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.CertificationAuthorityTreeDto;
import com.example.ca.service.dto.CertificationAuthorityViewDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.RootCertificationAuthorityEnrollDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import com.example.ca.util.FileContentExtractor;
import com.example.ca.util.StringUtil;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

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

    @GetMapping("/certificates/root/register")
    public String showRegisterForm() {
        return "root-ca-register";
    }

    @PostMapping("/certificates/enroll-root")
    public String enrollRootCa(
        @RequestParam(required = false) String certificateText,
        @RequestParam(required = false) String privateKeyText,
        @RequestParam(required = false) MultipartFile certificateFile,
        @RequestParam(required = false) MultipartFile privateKeyFile
    ) {
        String certificate = resolveInput("인증서", certificateText, certificateFile);
        String privateKey = resolveInput("개인키", privateKeyText, privateKeyFile);

        Long certificateId = certificateService.enrollRootCertificationAuthority(
            new RootCertificationAuthorityEnrollDto(certificate, privateKey)
        );

        return "redirect:/ca/" + certificateId;
    }

    private String resolveInput(String name, String text, MultipartFile file) {
        if (!StringUtil.isEmpty(text)) {
            return text;
        }
        if (file != null && !file.isEmpty()) {
            return FileContentExtractor.extractContent(file);
        }
        throw new IllegalArgumentException(name + " 입력이 필요합니다.");
    }
}
