package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AddCertificateToCaUserRequestDTO {
    
    @NotBlank(message = "CA user ID is required")
    private String caUserId;
    
    @NotBlank(message = "Certificate serial number is required")
    private String newCertificateSerialNumber;
}
