package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateCertificateRequestDTO {
    
    @NotBlank(message = "Signing organization is required")
    private String signingOrganization;
    
    @NotBlank(message = "Common name is required")
    private String commonName;
    
    @NotBlank(message = "Organization is required")
    private String organization;
    
    @NotBlank(message = "Organizational unit is required")
    private String organizationalUnit;
    
    @NotBlank(message = "Email is required")
    private String email;
    
    @NotBlank(message = "Country is required")
    private String country;
    
    private LocalDateTime notBefore;
    private LocalDateTime notAfter;
    
    private List<String> keyUsage;
    private List<String> extendedKeyUsage;
    private List<String> subjectAlternativeNames;
    private List<String> issuerAlternativeNames;
    private String nameConstraints;
    private String basicConstraints;
    private String certificatePolicy;
}
