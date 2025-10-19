package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Basic CA certificate information DTO for EE users.
 * Contains only the essential information needed to select a CA for certificate requests.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BasicCACertificateDTO {
    
    /**
     * Certificate serial number - unique identifier
     */
    private String serialNumber;
    
    /**
     * Common Name (CN) from the certificate subject
     */
    private String commonName;
    
    /**
     * Organization (O) from the certificate subject
     */
    private String organization;
    
    /**
     * Organizational Unit (OU) from the certificate subject
     */
    private String organizationalUnit;
}

