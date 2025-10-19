package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.CSRStatus;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CSRDTO {
    
    private Long id;
    private String csrData;
    private CSRStatus status;
    private UserDTO requester;
    private CertificateDTO selectedCA;
    private TemplateDTO selectedTemplate;
    private String subjectCN;
    private String subjectO;
    private String subjectOU;
    private String subjectC;
    private String subjectE;
    private String requestedExtensions;
    private String rejectionReason;
    private CertificateDTO issuedCertificate;
    private UserDTO processedBy;
    private LocalDateTime createdAt;
    private LocalDateTime processedAt;
    
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
    public static class CertificateDTO {
        private Long id;
        private String serialNumber;
        private String subjectCN;
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TemplateDTO {
        private Long id;
        private String name;
    }
}
