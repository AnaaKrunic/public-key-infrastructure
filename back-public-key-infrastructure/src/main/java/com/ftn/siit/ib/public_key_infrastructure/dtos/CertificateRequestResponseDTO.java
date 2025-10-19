package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.CSRStatus;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateRequestResponseDTO {
    
    private String id;
    private LocalDateTime submittedOn;
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String email;
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
    private CSRStatus status;
}
