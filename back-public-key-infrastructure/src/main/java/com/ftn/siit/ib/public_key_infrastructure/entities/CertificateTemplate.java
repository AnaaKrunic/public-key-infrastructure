package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_templates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateTemplate {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String name;  // Template name (e.g., "Web Server Template")
    
    @ManyToOne
    @JoinColumn(name = "ca_issuer_id", nullable = false)
    private User caIssuer;  // CA_USER who created this template
    
    @ManyToOne
    @JoinColumn(name = "issuer_certificate_id", nullable = false)
    private Certificate issuerCertificate;  // CA certificate to use for signing
    
    // ===== Validation Patterns (Regex) =====
    @Column(length = 500)
    private String commonNamePattern;  // Regex for CN validation (e.g., ".*\\.example\\.com")
    
    @Column(length = 500)
    private String sanPattern;  // Regex for SAN validation
    
    // ===== Certificate Constraints =====
    @Column(nullable = false)
    private Integer ttlDays;  // Maximum validity period in days
    
    // ===== Default Extensions =====
    @Column(length = 500)
    private String keyUsage;  // Default Key Usage extensions
    
    @Column(length = 500)
    private String extendedKeyUsage;  // Default Extended Key Usage
    
    // ===== Metadata =====
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
