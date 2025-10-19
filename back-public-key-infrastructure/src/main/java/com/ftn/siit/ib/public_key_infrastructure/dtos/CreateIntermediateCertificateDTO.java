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
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateIntermediateCertificateDTO {
    
    @NotNull(message = "Issuer certificate ID is required")
    private Long issuerCertificateId;
    
    @NotBlank(message = "Subject CN is required")
    @Size(max = 64, message = "Subject CN must not exceed 64 characters")
    private String subjectCN;
    
    @Size(max = 64, message = "Subject O must not exceed 64 characters")
    private String subjectO;
    
    @Size(max = 64, message = "Subject OU must not exceed 64 characters")
    private String subjectOU;
    
    @Size(max = 64, message = "Subject L must not exceed 64 characters")
    private String subjectL;
    
    @Size(max = 64, message = "Subject ST must not exceed 64 characters")
    private String subjectST;
    
    @Pattern(regexp = "^[A-Z]{2}$", message = "Subject C must be a 2-letter ISO country code")
    private String subjectC;
    
    @Pattern(regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", message = "Invalid email format")
    private String subjectE;
    
    @NotNull(message = "Validity days is required")
    @Min(value = 365, message = "Validity must be at least 365 days")
    @Max(value = 3650, message = "Validity must not exceed 3650 days (10 years)")
    private Integer validityDays;
    
    @NotNull(message = "Key size is required")
    @Min(value = 2048, message = "Key size must be at least 2048 bits")
    @Max(value = 4096, message = "Key size must not exceed 4096 bits")
    private Integer keySize;
    
    @NotNull(message = "Key usage is required")
    private List<String> keyUsage;
    
    @NotNull(message = "Basic constraints is required")
    private BasicConstraintsDTO basicConstraints;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BasicConstraintsDTO {
        @NotNull(message = "CA flag is required")
        private Boolean ca;
        
        private Integer pathLength;
    }
}
