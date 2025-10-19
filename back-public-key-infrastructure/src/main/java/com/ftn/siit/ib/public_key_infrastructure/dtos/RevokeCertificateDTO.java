package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevokeCertificateDTO {
    
    @NotBlank(message = "Revocation reason is required")
    @Pattern(regexp = "^(keyCompromise|cACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL|privilegeWithdrawn|aACompromise)$", 
             message = "Invalid revocation reason. Must be one of: keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise")
    private String reason;
}
