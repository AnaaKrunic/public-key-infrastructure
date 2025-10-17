package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_signing_requests")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateSigningRequest {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // ===== CSR Data =====
    @Column(nullable = false, columnDefinition = "TEXT")
    private String csrData;  // PEM format CSR (-----BEGIN CERTIFICATE REQUEST-----)
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CSRStatus status = CSRStatus.PENDING;
    
    // ===== Requester Information =====
    @ManyToOne
    @JoinColumn(name = "requester_id", nullable = false)
    private User requester;  // User who submitted the CSR

    @ManyToOne
    @JoinColumn(name = "requested_for_id")
    private User requestedFor; // End user for whom the certificate is requested

    @ManyToOne
    @JoinColumn(name = "requested_from_id")
    private User requestedFrom; // CA user expected to process the CSR
    
    // ===== CA Selection =====
    @ManyToOne
    @JoinColumn(name = "selected_ca_id", nullable = false)
    private Certificate selectedCA;  // CA certificate to sign this CSR
    
    @ManyToOne
    @JoinColumn(name = "template_id")
    private CertificateTemplate selectedTemplate;  // Optional template for validation
    
    // ===== Subject DN Fields (extracted from CSR) =====
    @Column(nullable = false)
    private String subjectCN;
    
    private String subjectO;
    private String subjectOU;
    
    @Column(length = 2)
    private String subjectC;
    
    private String subjectE;
    
    // ===== Requested Extensions =====
    @Column(columnDefinition = "TEXT")
    private String requestedExtensions;  // JSON format: {"keyUsage": [...], "extendedKeyUsage": [...]}
    
    // ===== Processing Information =====
    private String rejectionReason;  // Reason if status = REJECTED
    
    @OneToOne
    @JoinColumn(name = "issued_certificate_id")
    private Certificate issuedCertificate;  // Certificate created when approved
    
    @ManyToOne
    @JoinColumn(name = "processed_by_id")
    private User processedBy;  // CA_USER or ADMIN who processed this CSR
    
    // ===== Timestamps =====
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    private LocalDateTime processedAt;  // When approved/rejected
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
