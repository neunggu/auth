package com.quackquack.auth.exception;

import lombok.Getter;

public class AuthException extends RuntimeException {
    @Getter
    protected String errorCode;
    public AuthException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
}
