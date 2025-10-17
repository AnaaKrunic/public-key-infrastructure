package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum Role {
    ADMIN,        // System administrator - full access
    CA_USER,      // Certificate Authority user - can issue certs for their org
    EE_USER       // End Entity user - can request certificates
}

