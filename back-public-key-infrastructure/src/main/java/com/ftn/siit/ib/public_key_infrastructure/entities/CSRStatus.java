package com.ftn.siit.ib.public_key_infrastructure.entities;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum CSRStatus {
    PENDING,   // CSR awaiting CA approval
    APPROVED,  // CSR approved and certificate issued
    REJECTED;  // CSR rejected by CA
    
    @JsonValue
    public String getValue() {
        return this.name();
    }
    
    @JsonCreator
    public static CSRStatus fromValue(String value) {
        for (CSRStatus status : CSRStatus.values()) {
            if (status.name().equalsIgnoreCase(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown CSRStatus: " + value);
    }
}

