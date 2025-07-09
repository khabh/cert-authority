package com.example.ca.exception;

public class CaException extends RuntimeException {

    public CaException(String message) {
        super(message);
    }

    public CaException(String message, Object... args) {
        super(String.format(message, args));
    }
}
