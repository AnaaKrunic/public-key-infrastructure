package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "revoked_certificates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RevokedCertificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "certificate_id", nullable = false)
    private Certificate certificate;

    @ManyToOne
    @JoinColumn(name = "issuer_certificate_id")
    private Certificate issuerCertificate;

    @ManyToOne
    @JoinColumn(name = "revoked_by_id")
    private User revokedBy;

    @Column(nullable = false, length = 64)
    private String certificateSerialNumber;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RevocationReason revocationReason;

    @Column(nullable = false)
    private LocalDateTime revokedAt;

    @PrePersist
    protected void onCreate() {
        if (revokedAt == null) {
            revokedAt = LocalDateTime.now();
        }
    }
}

