package com.ftn.siit.ib.public_key_infrastructure.exceptions;

public class TemplateConstraintViolationException extends RuntimeException {
    public TemplateConstraintViolationException(String message) {
        super(message);
    }

    public TemplateConstraintViolationException(String message, Throwable cause) {
        super(message, cause);
    }
}
