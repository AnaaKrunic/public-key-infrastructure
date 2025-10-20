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
    private String name;  // Template name (e.g., "Employee Certificate Template")
    
    @Column(nullable = false)
    private String caIssuerSerialNumber;  // CA certificate serial number that will issue certificates
    
    // ===== Validation Patterns (Regex) =====
    @Column(nullable = false, length = 500)
    private String cnRegex;  // Regex for CN validation (e.g., ".*\\.ftn\\.com")
    
    @Column(nullable = false, length = 500)
    private String sanRegex;  // Regex for SAN validation (e.g., ".*\\.ftn\\.com")
    
    // ===== Certificate Constraints =====
    @Column(nullable = false)
    private Integer ttl;  // TTL (time to live) in days - maximum validity period
    
    // ===== Default Extensions =====
    @Column(nullable = false, length = 500)
    private String keyUsage;  // Default Key Usage extensions
    
    @Column(nullable = false, length = 500)
    private String extendedKeyUsage;  // Default Extended Key Usage
    
    // ===== Metadata =====
    @ManyToOne
    @JoinColumn(name = "created_by_id", nullable = false)
    private User createdBy;  // CA_USER who created this template
    
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
