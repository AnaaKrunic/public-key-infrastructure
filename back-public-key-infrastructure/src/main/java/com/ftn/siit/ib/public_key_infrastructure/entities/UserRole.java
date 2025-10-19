package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum UserRole {
    ADMIN("Administrator", "Full system access and user management"),
    CA_USER("CA User", "Certificate Authority operations"),
    USER("User", "Basic certificate operations");

    private final String displayName;
    private final String description;

    UserRole(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }
}
