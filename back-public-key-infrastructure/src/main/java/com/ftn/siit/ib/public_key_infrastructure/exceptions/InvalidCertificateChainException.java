package com.ftn.siit.ib.public_key_infrastructure.exceptions;

public class InvalidCertificateChainException extends RuntimeException {
    public InvalidCertificateChainException(String message) {
        super(message);
    }

    public InvalidCertificateChainException(String message, Throwable cause) {
        super(message, cause);
    }
}
