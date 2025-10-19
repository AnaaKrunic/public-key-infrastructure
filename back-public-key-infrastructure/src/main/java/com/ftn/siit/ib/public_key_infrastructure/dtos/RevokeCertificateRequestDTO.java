package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.RevocationReason;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevokeCertificateRequestDTO {
    
    @NotBlank(message = "Serial number is required")
    private String serialNumber;
    
    @NotNull(message = "Revocation reason is required")
    private RevocationReason revocationReason;
}
