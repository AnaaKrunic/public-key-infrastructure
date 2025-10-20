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
    private String caIssuerSerialNumber;
    private String cnRegex;
    private String sanRegex;
    private Integer ttl;
    private String keyUsage;
    private String extendedKeyUsage;
    private UserDTO createdBy;
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
}
