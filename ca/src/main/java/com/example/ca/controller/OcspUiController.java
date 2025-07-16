package com.example.ca.controller;

import com.example.ca.exception.CaException;
import com.example.ca.service.OcspService;
import com.example.ca.util.CertificateUtil;
import com.example.ca.util.FileContentExtractor;
import java.security.cert.X509Certificate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("/ocsp")
@RequiredArgsConstructor
public class OcspUiController {

    private final OcspService ocspService;

    @GetMapping
    public String showOcspPage() {
        return "ocsp";
    }

    @PostMapping("/check/file")
    public String checkStatusFromFile(@RequestParam("certFile") MultipartFile certFile, Model model) {
        try {
            String certPem = FileContentExtractor.extractContent(certFile);
            X509Certificate certificate = CertificateUtil.getCertificate(certPem);
            String serial = certificate.getSerialNumber().toString(16).toUpperCase();
            model.addAttribute("serial", serial);
            model.addAttribute("status", ocspService.checkCertificateStatus(serial));
        } catch (Exception e) {
            throw new CaException("OCSP 조회 중 오류 발생: " + e.getMessage());
        }

        return "fragments/ca-status :: result";
    }

    @PostMapping("/check/serial")
    public String checkStatusFromSerial(@RequestParam("serial") String serialHex, Model model) {
        try {
            model.addAttribute("serial", serialHex);
            model.addAttribute("status", ocspService.checkCertificateStatus(serialHex));
        } catch (NumberFormatException e) {
            throw new CaException("올바른 HEX 형식의 일련번호를 입력해주세요.");
        }
        return "fragments/ca-status :: result";
    }
}