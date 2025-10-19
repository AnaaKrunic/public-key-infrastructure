package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.RevocationReason;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevokedCertificateResponseDTO {
    
    private String serialNumber;
    private String prettySerialNumber;
    private String issuedBy;
    private String issuedTo;
    private String decryptedCertificate;
    private RevocationReason revocationReason;
}
