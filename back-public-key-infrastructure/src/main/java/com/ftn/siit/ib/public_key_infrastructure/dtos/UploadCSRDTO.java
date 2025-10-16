package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;

@Data
public class UploadCSRDTO {
    private String csrData; // PEM-encoded CSR
    private Long selectedCAId;
    private Long selectedTemplateId; // Optional
}

