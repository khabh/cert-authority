package com.example.ca.service;

import com.example.ca.service.dto.RootCertificateIssueDto;
import java.util.stream.IntStream;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("local")
@RequiredArgsConstructor
class DataInitializer implements ApplicationRunner {

    private final CertificateService certificateService;

    @Override
    public void run(ApplicationArguments args) {
        IntStream.range(0, 10)
                 .mapToObj(number -> new RootCertificateIssueDto(
                     "cn" + number,
                     "organization" + number,
                     "unit" + number,
                     "Seoul",
                     "Gang",
                     "KR"
                 ))
                 .forEach(certificateService::issueRootCertificate);
    }
}
