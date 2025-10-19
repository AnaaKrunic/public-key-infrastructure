package com.ftn.siit.ib.public_key_infrastructure.exceptions;

public class InvalidCertificateException extends RuntimeException {
    public InvalidCertificateException(String message) {
        super(message);
    }

    public InvalidCertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
