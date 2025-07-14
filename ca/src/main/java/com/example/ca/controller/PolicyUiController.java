package com.example.ca.controller;

import com.example.ca.service.CertificateService;
import com.example.ca.service.PolicyService;
import com.example.ca.service.dto.CertificationAuthorityViewDto;
import com.example.ca.service.dto.PolicyCreateDto;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class PolicyUiController {

    private final CertificateService certificateService;
    private final PolicyService policyService;

    @GetMapping("/policies/create")
    public String createPolicyPage(Model model) {
        List<CertificationAuthorityViewDto> authorities = certificateService.getCertificationAuthorityView();
        model.addAttribute("authorities", authorities);

        return "policy";
    }

    @PostMapping("/policies")
    public String createPolicy(@Valid @ModelAttribute PolicyCreateDto dto) {
        policyService.createPolicy(dto);
        return "redirect:/dashboard";
    }

    @GetMapping("/certificates/sub/create/v2")
    public String showSubCaForm(Model model) {
        model.addAttribute("policies", policyService.getPolicies());

        return "sub-ca-with-policy";
    }
}
