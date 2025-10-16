package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateDTO {
    
    private Long id;
    private String serialNumber;
    private String subjectCN;
    private String subjectO;
    private String subjectOU;
    private String subjectL;
    private String subjectST;
    private String subjectC;
    private String subjectE;
    private String subjectDN;
    private String issuerCN;
    private String issuerO;
    private String issuerOU;
    private String issuerL;
    private String issuerST;
    private String issuerC;
    private String issuerE;
    private String issuerDN;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private CertificateType certificateType;
    private CertificateStatus status;
    private String revocationReason;
    private LocalDateTime revocationDate;
    private String publicKey;
    private String certificateData;
    private String keyUsage;
    private String extendedKeyUsage;
    private String subjectAlternativeNames;
    private String crlDistributionPoint;
    private UserDTO owner;
    private CertificateDTO issuerCertificate;
    private TemplateDTO template;
    private LocalDateTime createdAt;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserDTO {
        private Long id;
        private String email;
        private String firstName;
        private String lastName;
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TemplateDTO {
        private Long id;
        private String name;
    }
}
