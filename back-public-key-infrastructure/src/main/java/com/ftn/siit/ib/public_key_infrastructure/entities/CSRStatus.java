package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum CSRStatus {
    PENDING,   // CSR awaiting CA approval
    APPROVED,  // CSR approved and certificate issued
    REJECTED   // CSR rejected by CA
}

