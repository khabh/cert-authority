package com.example.ca;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public Object handleException(HttpServletRequest request, Exception ex) {
        boolean isHtmx = "true".equals(request.getHeader("HX-Request"));

        String errorMessage = ex.getMessage() != null ? ex.getMessage() : "알 수 없는 오류가 발생했습니다.";

        if (isHtmx) {
            String encodedMsg = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
            String redirectUrl = "/error?message=" + encodedMsg;

            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .header("HX-Redirect", redirectUrl)
                .build();
        } else {
            ModelAndView mav = new ModelAndView("error");
            mav.setStatus(HttpStatus.BAD_REQUEST);
            mav.addObject("message", errorMessage);
            return mav;
        }
    }
}