package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum CertificateStatus {
    ACTIVE,     // Certificate is active and valid
    DORMANT,    // Certificate is not yet valid (before notBefore date)
    EXPIRED,    // Certificate has passed its notAfter date
    REVOKED,    // Certificate has been revoked
    INVALID,    // Certificate has other issues (signature validation, etc.)
    CIRCULAR,   // Certificate chain contains circular references
    PROHIBITED  // Certificate violates path length constraints
}

