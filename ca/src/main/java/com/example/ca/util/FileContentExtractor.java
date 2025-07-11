package com.example.ca.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.web.multipart.MultipartFile;

public class FileContentExtractor {

    public static String extractContent(MultipartFile file) {
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
            throw new RuntimeException("파일을 문자열로 변환하는 데 실패했습니다.", e);
        }
    }
}