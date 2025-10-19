package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateTemplateDTO {
    
    @NotBlank(message = "Template name is required")
    @Size(max = 100, message = "Template name must not exceed 100 characters")
    private String name;
    
    @NotNull(message = "Issuer certificate ID is required")
    private Long issuerCertificateId;
    
    @Pattern(regexp = "^.*$", message = "Invalid common name pattern")
    private String commonNamePattern;
    
    @Pattern(regexp = "^.*$", message = "Invalid SAN pattern")
    private String sanPattern;
    
    @NotNull(message = "TTL days is required")
    @Min(value = 1, message = "TTL must be at least 1 day")
    @Max(value = 3650, message = "TTL must not exceed 3650 days (10 years)")
    private Integer ttlDays;
    
    private String keyUsage;
    
    private String extendedKeyUsage;
}
