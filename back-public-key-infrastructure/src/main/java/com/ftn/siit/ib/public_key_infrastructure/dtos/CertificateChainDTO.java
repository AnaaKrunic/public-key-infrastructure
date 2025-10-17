package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import java.util.List;

@Data
public class CertificateChainDTO {
    private List<CertificateDTO> certificates; // Ordered from end-entity to root
    private boolean valid;
    private String validationMessage;
}

