package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DownloadCertificateRequestDTO {
    
    @NotBlank(message = "Certificate serial number is required")
    private String certificateSerialNumber;
    
    @NotBlank(message = "Password is required")
    private String password;
}
