package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.CertificateIssueDto;
import com.example.ca.service.dto.CertificationAuthorityTreeDto;
import com.example.ca.service.dto.CertificationAuthorityViewDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.RootCertificationAuthorityEnrollDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import jakarta.validation.Valid;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
    public String showRegisterForm(Model model) {
        return "root-ca-register";
    }

    @PostMapping("/certificates/enroll-root")
    public String enrollRootCa(
        @RequestParam(required = false) String certificateText,
        @RequestParam(required = false) String privateKeyText,
        @RequestParam(required = false) MultipartFile certificateFile,
        @RequestParam(required = false) MultipartFile privateKeyFile
    ) {
        if ((isEmpty(certificateText) && (certificateFile == null || certificateFile.isEmpty()))
            || (isEmpty(privateKeyText) && (privateKeyFile == null || privateKeyFile.isEmpty()))) {
            throw new RuntimeException("올바르지 않은 입력입니다.");
        }
        if (certificateText.isEmpty()) {

            certificateText = multipartFileToString(certificateFile);
        }
        if (privateKeyText.isEmpty()) {
            privateKeyText = multipartFileToString(privateKeyFile);
        }

        Long certificateId = certificateService.enrollRootCertificationAuthority(new RootCertificationAuthorityEnrollDto(certificateText, privateKeyText));

        return "redirect:/ca/" + certificateId;
    }

    private boolean isEmpty(String s) {
        return s == null || s.isBlank();
    }

    private String multipartFileToString(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return null;
        }
        try {
            byte[] bytes = file.getBytes();

            String originalFilename = file.getOriginalFilename();
            if (originalFilename != null) {
                String lowerName = originalFilename.toLowerCase();
                if (lowerName.endsWith(".der") || lowerName.endsWith(".cer")) {
                    return Base64.getEncoder().encodeToString(bytes);
                }
            }
            return new String(bytes, StandardCharsets.UTF_8);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
