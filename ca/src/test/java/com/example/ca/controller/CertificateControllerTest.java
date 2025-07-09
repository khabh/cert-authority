package com.example.ca.controller;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.ca.service.CertificateService;
import com.example.ca.service.dto.CertificateDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(CertificateController.class)
class CertificateControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private CertificateService certificateService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Root CA 발급 요청 시 200 OK와 인증서를 반환한다.")
    void issueRootCertificate() throws Exception {
        RootCertificateIssueDto request = new RootCertificateIssueDto(
            "Test CN", "Org", "Unit", "Seoul", "Seoul", "KR"
        );

        CertificateDto response = new CertificateDto("-----BEGIN CERTIFICATE-----\n...certificate...\n-----END CERTIFICATE-----");

        when(certificateService.issueRootCertificate(request)).thenReturn(response);

        mockMvc.perform(post("/api/certificates/root")
                   .contentType(MediaType.APPLICATION_JSON)
                   .content(objectMapper.writeValueAsString(request)))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.certificate").value(response.certificate()));
    }
}