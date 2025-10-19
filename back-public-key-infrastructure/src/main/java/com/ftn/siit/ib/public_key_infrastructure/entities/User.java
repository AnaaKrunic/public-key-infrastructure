package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.EE_USER;  // Default role

    @Column(length = 255)
    private String organization;

    @Column(nullable = false)

    private boolean enabled = false;

    @Column(nullable = false)
    private boolean emailConfirmed = false;

    @Column(unique = true)
    private String activationToken;

    private LocalDateTime tokenExpiration;

    private String mfaSecret;

    @Column(nullable = false)
    private boolean mfaEnabled = false;
    
    private LocalDateTime refreshTokenExpiration;

    @Column(length = 512)
    private String refreshToken;

    private LocalDateTime refreshTokenExpiresAt;
    public User(Long id, String email, String passwordHash, String firstName, String lastName, String organization,
                Role role, boolean enabled, String activationToken, LocalDateTime tokenExpiration, String mfaSecret, boolean mfaEnabled,
                String refreshToken, LocalDateTime refreshTokenExpiration) {
        this.id = id;
        this.email = email;
        this.passwordHash = passwordHash;
        this.firstName = firstName;
        this.lastName = lastName;
        this.organization = organization;
        this.role = role;
        this.enabled = enabled;
        this.activationToken = activationToken;
        this.tokenExpiration = tokenExpiration;
        this.mfaSecret = mfaSecret;
        this.mfaEnabled = mfaEnabled;
        this.refreshToken = refreshToken;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    // Many-to-many relationship with certificates
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "user_certificates",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "certificate_id")
    )
    private List<Certificate> myCertificates = new ArrayList<>();

}
