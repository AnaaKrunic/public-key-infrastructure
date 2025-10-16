package com.ftn.siit.ib.public_key_infrastructure.dtos;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TemplateDTO {
    
    private Long id;
    private String name;
    private UserDTO caIssuer;
    private CertificateDTO issuerCertificate;
    private String commonNamePattern;
    private String sanPattern;
    private Integer ttlDays;
    private String keyUsage;
    private String extendedKeyUsage;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
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
}
