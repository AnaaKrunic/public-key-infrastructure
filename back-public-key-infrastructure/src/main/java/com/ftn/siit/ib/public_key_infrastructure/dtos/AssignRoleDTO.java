package com.ftn.siit.ib.public_key_infrastructure.dtos;

import com.ftn.siit.ib.public_key_infrastructure.entities.UserRole;

public class AssignRoleDTO {
    private String email;
    private UserRole role;

    public AssignRoleDTO() {}

    public AssignRoleDTO(String email, UserRole role) {
        this.email = email;
        this.role = role;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }
}
