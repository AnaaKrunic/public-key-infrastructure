package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "certificates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Certificate {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 64)
    private String serialNumber;  // 128-bit hex string (32 chars) or larger
    
    // ===== X.500 Subject Distinguished Name Fields =====
    @Column(nullable = false)
    private String subjectCN;  // Common Name (e.g., "www.example.com")
    
    private String subjectO;   // Organization (e.g., "Example Corp")
    private String subjectOU;  // Organizational Unit (e.g., "IT Department")
    private String subjectL;   // Locality/City (e.g., "San Francisco")
    private String subjectST;  // State/Province (e.g., "California")
    
    @Column(length = 2)
    private String subjectC;   // Country (2-letter ISO code, e.g., "US")
    
    private String subjectE;   // Email Address
    
    @Column(nullable = false, length = 500)
    private String subjectDN;  // Full DN string (e.g., "CN=www.example.com,O=Example Corp,C=US")
    
    // ===== X.500 Issuer Distinguished Name Fields =====
    @Column(nullable = false)
    private String issuerCN;
    
    private String issuerO;
    private String issuerOU;
    private String issuerL;
    private String issuerST;
    
    @Column(length = 2)
    private String issuerC;
    
    private String issuerE;
    
    @Column(nullable = false, length = 500)
    private String issuerDN;  // Full issuer DN string
    
    // ===== Validity Period =====
    @Column(nullable = false)
    private LocalDateTime validFrom;
    
    @Column(nullable = false)
    private LocalDateTime validTo;
    
    // ===== Certificate Type & Status =====
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType certificateType;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateStatus status = CertificateStatus.VALID;
    
    // ===== Revocation Information =====
    private String revocationReason;  // X.509 standard reasons
    private LocalDateTime revocationDate;
    
    // ===== Cryptographic Material =====
    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey;  // PEM format (-----BEGIN PUBLIC KEY-----)
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPrivateKey;  // Base64-encoded AES-256-GCM ciphertext
    
    @Column(nullable = false, length = 24)
    private String encryptionIV;  // Base64-encoded 12-byte IV
    
    @Column(nullable = false, length = 24)
    private String encryptionTag;  // Base64-encoded 16-byte authentication tag
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String certificateData;  // Full X.509 certificate in PEM format
    
    // ===== X.509 Extensions =====
    @Column(length = 500)
    private String keyUsage;  // Comma-separated: "digitalSignature,keyEncipherment,keyCertSign"
    
    @Column(length = 500)
    private String extendedKeyUsage;  // Comma-separated: "serverAuth,clientAuth"
    
    @Column(length = 1000)
    private String subjectAlternativeNames;  // Comma-separated SANs
    
    @Column(length = 500)
    private String crlDistributionPoint;  // URL to CRL
    
    // ===== Relationships =====
    @ManyToOne
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;  // User who owns this certificate
    
    @ManyToOne
    @JoinColumn(name = "issuer_certificate_id")
    private Certificate issuerCertificate;  // Parent CA certificate (null for Root)
    
    @ManyToOne
    @JoinColumn(name = "template_id")
    private CertificateTemplate template;  // Template used (if any)
    
    // ===== Metadata =====
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
