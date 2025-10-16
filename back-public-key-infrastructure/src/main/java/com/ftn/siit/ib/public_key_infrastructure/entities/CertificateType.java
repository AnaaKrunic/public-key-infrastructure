package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum CertificateType {
    ROOT,          // Self-signed root CA certificate
    INTERMEDIATE,  // Intermediate CA certificate (signed by Root or another Intermediate)
    END_ENTITY     // End-entity certificate (leaf certificate for users/servers)
}

