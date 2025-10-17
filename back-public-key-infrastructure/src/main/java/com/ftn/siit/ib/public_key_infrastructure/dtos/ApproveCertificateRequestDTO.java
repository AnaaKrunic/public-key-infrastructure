package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApproveCertificateRequestDTO {
    
    @NotBlank(message = "Request ID is required")
    private String requestId;
    
    @NotNull(message = "Request form is required")
    private CreateEndEntityCertificateDTO requestForm;
}
