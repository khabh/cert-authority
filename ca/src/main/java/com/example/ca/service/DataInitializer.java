package com.example.ca.service;

import com.example.ca.service.dto.PolicyCreateDto;
import com.example.ca.service.dto.RootCertificateIssueDto;
import com.example.ca.service.dto.SubCertificateIssueDto;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@Profile("local")
@RequiredArgsConstructor
class DataInitializer implements ApplicationRunner {

    private final CertificateService certificateService;
    private final PolicyService policyService;
    private final KeyStoreManager keyStoreManager;

    @Override
    public void run(ApplicationArguments args) {
        keyStoreManager.removeAll();
        IntStream.range(1, 4)
                 .mapToObj(number -> new RootCertificateIssueDto(
                     "cn" + number,
                     "organization" + number,
                     "unit" + number,
                     "Seoul",
                     "Gang",
                     "KR"
                 ))
                 .forEach(certificateService::issueRootCertificate);
        LongStream.range(2, 4)
                  .mapToObj(number -> new SubCertificateIssueDto(
                      number,
                      "cn" + (number + 2),
                      "organization" + number,
                      "unit" + number,
                      "Seoul",
                      "Gang",
                      "KR"
                  ))
                  .forEach(certificateService::issueSubCertificate);
        LongStream.range(4, 6)
                  .mapToObj(number -> new SubCertificateIssueDto(
                      number,
                      "cn" + (number + 2),
                      "organization" + number,
                      "unit" + number,
                      "Seoul",
                      "Gang",
                      "KR"
                  ))
                  .forEach(certificateService::issueSubCertificate);
        LongStream.range(1, 4)
                  .mapToObj(number -> new PolicyCreateDto(
                      "policy" + number,
                      number,
                      "po" + number,
                      "pou" + number,
                      "AU"
                  ))
                  .forEach(policyService::createPolicy);
        log.info("Data Initialized successfully");
    }
}
