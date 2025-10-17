package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {
    
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private Role role;
    private OrganizationDTO organization;
    private boolean enabled;
    private boolean emailConfirmed;
    private boolean mfaEnabled;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OrganizationDTO {
        private Long id;
        private String name;
    }
}
