package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.entities.*;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.RevokedCertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.CRLGeneratorService;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.UserKeyService;
import com.ftn.siit.ib.public_key_infrastructure.dtos.RevokedCertificateResponseDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.RevokeCertificateRequestDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.CertificateDTO;
import org.bouncycastle.cert.X509CRLHolder;
import org.hibernate.Hibernate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * CRLService manages Certificate Revocation Lists (CRLs) for CA certificates.
 * 
 * This service handles:
 * - CRL generation for CA certificates
 * - CRL retrieval for public validation
 * - Automatic CRL updates when certificates are revoked
 * - Revocation status checking
 * 
 * CRLs are generated according to RFC 5280 and include all certificates
 * revoked by a specific CA. They are publicly accessible for certificate
 * validation purposes.
 */
@Service
@Transactional
public class CRLService {

    private final CertificateRepository certificateRepository;
    private final RevokedCertificateRepository revokedCertificateRepository;
    private final CRLGeneratorService crlGeneratorService;
    private final EncryptionService encryptionService;
    private final UserKeyService userKeyService;

    public CRLService(
            CertificateRepository certificateRepository,
            RevokedCertificateRepository revokedCertificateRepository,
            CRLGeneratorService crlGeneratorService,
            EncryptionService encryptionService,
            UserKeyService userKeyService) {
        this.certificateRepository = certificateRepository;
        this.revokedCertificateRepository = revokedCertificateRepository;
        this.crlGeneratorService = crlGeneratorService;
        this.encryptionService = encryptionService;
        this.userKeyService = userKeyService;
    }

    /**
     * Generates a Certificate Revocation List for a CA certificate.
     * 
     * Process:
     * 1. Validate caCertificate is a valid CA (ROOT or INTERMEDIATE)
     * 2. Find all certificates issued by this CA with status REVOKED
     * 3. Extract serial numbers and revocation dates
     * 4. Use CRLGeneratorService to build CRL with proper extensions
     * 5. Decrypt CA's private key to sign the CRL
     * 6. Store CRL in database or file system with thisUpdate and nextUpdate times
     * 
     * CRL validity period:
     * - thisUpdate: Current timestamp
     * - nextUpdate: thisUpdate + 7 days (configurable)
     * 
     * @param caCertificate The CA certificate for which to generate the CRL
     * @return Byte array containing the CRL in DER format
     * @throws IllegalArgumentException if caCertificate is null
     * @throws ValidationException if caCertificate is not a valid CA
     * @throws CryptoException if CRL signing fails
     */
    public byte[] generateCRL(Certificate caCertificate) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }

        // Validate that the certificate is a CA
        if (caCertificate.getCertificateType() != CertificateType.ROOT && 
            caCertificate.getCertificateType() != CertificateType.INTERMEDIATE) {
            throw new ValidationException("Certificate must be a CA certificate (ROOT or INTERMEDIATE)");
        }

        // Find all revoked certificates issued by this CA
        List<Certificate> revokedCertificates = certificateRepository.findRevokedCertificatesByIssuer(caCertificate);
        
        // Extract serial numbers
        List<BigInteger> revokedSerialNumbers = revokedCertificates.stream()
            .map(cert -> new BigInteger(cert.getSerialNumber()))
            .toList();

        try {
            // Parse the CA certificate from PEM format
            X509Certificate x509CACertificate = parseX509CertificateFromPEM(caCertificate.getCertificateData());
            
            // Decrypt the CA's private key
            PrivateKey caPrivateKey = decryptCAPrivateKey(caCertificate);
            
            // Get CRL distribution point URL
            String crlDistributionPoint = getCRLDistributionPoint(caCertificate);
            
            // Generate the CRL using CRLGeneratorService
            X509CRLHolder crlHolder = crlGeneratorService.generateCRL(
                x509CACertificate, 
                caPrivateKey, 
                revokedSerialNumbers, 
                crlDistributionPoint
            );
            
            // Convert to DER format
            byte[] crlData = crlHolder.getEncoded();
            
            // Store the CRL
            storeCRL(caCertificate, crlData);
            
            return crlData;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CRL", e);
        }
    }

    /**
     * Retrieves the CRL for a CA certificate by its serial number.
     * 
     * This is a public endpoint (no authentication required) as CRLs
     * must be accessible for certificate validation.
     * 
     * Process:
     * 1. Find CA certificate by serial number
     * 2. Check if CRL exists and is still valid (before nextUpdate)
     * 3. If CRL is expired or doesn't exist, generate new CRL
     * 4. Return CRL in DER format
     * 
     * CRL Distribution Point URLs typically point to this endpoint:
     * http://pki.example.com/crl/{caSerialNumber}.crl
     * 
     * @param caSerialNumber The serial number of the CA certificate
     * @return Byte array containing the CRL in DER format
     * @throws IllegalArgumentException if caSerialNumber is null
     * @throws NotFoundException if CA certificate not found
     * @throws ValidationException if certificate is not a CA
     */
    public byte[] getCRL(String caSerialNumber) {
        if (caSerialNumber == null) {
            throw new IllegalArgumentException("CA serial number cannot be null");
        }

        // Find the CA certificate
        Optional<Certificate> caCertOpt = certificateRepository.findBySerialNumber(caSerialNumber);
        if (caCertOpt.isEmpty()) {
            throw new NotFoundException("CA certificate not found with serial number: " + caSerialNumber);
        }
        
        Certificate caCertificate = caCertOpt.get();
        
        // Validate that it's a CA certificate
        if (caCertificate.getCertificateType() != CertificateType.ROOT && 
            caCertificate.getCertificateType() != CertificateType.INTERMEDIATE) {
            throw new ValidationException("Certificate is not a CA certificate");
        }

        // Try to get existing CRL
        byte[] existingCRL = getStoredCRL(caCertificate);
        
        // If CRL exists and is still valid, return it
        if (existingCRL != null && isCRLValid(existingCRL)) {
            return existingCRL;
        }
        
        // Otherwise, generate a new CRL
        return generateCRL(caCertificate);
    }

    /**
     * Updates the CRL for a CA certificate after a certificate is revoked.
     * 
     * This method is called automatically by CertificateService when
     * a certificate is revoked to ensure CRLs are up-to-date.
     * 
     * Process:
     * 1. Generate new CRL with updated revocation list
     * 2. Update thisUpdate and nextUpdate timestamps
     * 3. Store new CRL, replacing the old one
     * 
     * @param caCertificate The CA certificate whose CRL should be updated
     * @throws IllegalArgumentException if caCertificate is null
     * @throws ValidationException if caCertificate is not a valid CA
     * @throws CryptoException if CRL generation fails
     */
    public void updateCRL(Certificate caCertificate) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }

        // Validate that the certificate is a CA
        if (caCertificate.getCertificateType() != CertificateType.ROOT && 
            caCertificate.getCertificateType() != CertificateType.INTERMEDIATE) {
            throw new ValidationException("Certificate must be a CA certificate (ROOT or INTERMEDIATE)");
        }

        // Generate a new CRL with updated revocation list
        generateCRL(caCertificate);
    }

    /**
     * Checks if a certificate is revoked by querying its status.
     * 
     * This is a fast local check that queries the database rather than
     * parsing CRLs. For external validation, use getCRL() and parse the CRL.
     * 
     * @param serialNumber The serial number of the certificate to check
     * @return true if the certificate is revoked, false if valid or not found
     * @throws IllegalArgumentException if serialNumber is null
     */
    public boolean checkRevocationStatus(String serialNumber) {
        if (serialNumber == null) {
            throw new IllegalArgumentException("Serial number cannot be null");
        }

        // Find the certificate by serial number
        Optional<Certificate> certOpt = certificateRepository.findBySerialNumber(serialNumber);
        if (certOpt.isEmpty()) {
            return false; // Certificate not found, consider it not revoked
        }
        
        Certificate certificate = certOpt.get();
        
        // Check if the certificate status is REVOKED
        return certificate.getStatus() == CertificateStatus.REVOKED;
    }

    /**
     * Gets the CRL distribution point URL for a CA certificate.
     * 
     * This URL is embedded in issued certificates' CRL Distribution Points
     * extension and should point to the getCRL endpoint.
     * 
     * @param caCertificate The CA certificate
     * @return CRL distribution point URL
     */
    public String getCRLDistributionPoint(Certificate caCertificate) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }

        // This would return the actual CRL distribution point URL
        // For now, return a placeholder URL
        return "http://pki.example.com/crl/" + caCertificate.getSerialNumber() + ".crl";
    }

    /**
     * Lists all revoked certificates for a CA.
     * 
     * This is used internally for CRL generation and for administrative
     * purposes (viewing revoked certificates).
     * 
     * @param caCertificate The CA certificate
     * @return List of revoked certificates
     * @throws IllegalArgumentException if caCertificate is null
     */
    private java.util.List<Certificate> getRevokedCertificates(Certificate caCertificate) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }

        // This would query the database for revoked certificates
        // For now, return an empty list
        return java.util.Collections.emptyList();
    }

    /**
     * Checks if a CRL is still valid (before nextUpdate time).
     * 
     * @param crlData The CRL data
     * @return true if CRL is still valid, false if expired
     */
    private boolean isCRLValid(byte[] crlData) {
        if (crlData == null) {
            return false;
        }

        // This would parse the CRL and check nextUpdate time
        // For now, return true (valid)
        return true;
    }

    /**
     * Stores a CRL in the database or file system.
     * 
     * @param caCertificate The CA certificate
     * @param crlData The CRL data in DER format
     */
    private void storeCRL(Certificate caCertificate, byte[] crlData) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }
        if (crlData == null) {
            throw new IllegalArgumentException("CRL data cannot be null");
        }

        // This would store the CRL in the database or file system
        // For now, do nothing (placeholder implementation)
    }

    /**
     * Retrieves stored CRL data for a CA certificate.
     * 
     * @param caCertificate The CA certificate
     * @return CRL data in DER format, or null if not found
     */
    private byte[] getStoredCRL(Certificate caCertificate) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }

        // This would retrieve the stored CRL from database or file system
        // For now, return null (not found)
        return null;
    }

    /**
     * Parses an X.509 certificate from PEM format.
     * 
     * @param pemData The PEM-encoded certificate data
     * @return X509Certificate object
     * @throws RuntimeException if parsing fails
     */
    private X509Certificate parseX509CertificateFromPEM(String pemData) {
        if (pemData == null || pemData.trim().isEmpty()) {
            throw new IllegalArgumentException("PEM data cannot be null or empty");
        }

        try {
            // Remove PEM headers and footers
            String cleanPem = pemData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64
            byte[] derData = java.util.Base64.getDecoder().decode(cleanPem);
            
            // Create certificate factory
            java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
            
            // Generate certificate from DER data
            return (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(derData)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse X.509 certificate from PEM", e);
        }
    }

    /**
     * Decrypts the CA's private key for CRL signing.
     * 
     * @param caCertificate The CA certificate
     * @return Decrypted private key
     * @throws RuntimeException if decryption fails
     */
    private PrivateKey decryptCAPrivateKey(Certificate caCertificate) {
        try {
            // Decode the encrypted private key components
            byte[] encryptedData = java.util.Base64.getDecoder().decode(caCertificate.getEncryptedPrivateKey());
            byte[] iv = java.util.Base64.getDecoder().decode(caCertificate.getEncryptionIV());
            byte[] tag = java.util.Base64.getDecoder().decode(caCertificate.getEncryptionTag());
            
            // Get the user key for the user who created this certificate
            byte[] userKey = userKeyService.getUserKey(caCertificate.getSignedBy().getId());
            
            // Decrypt the private key using the user's key
            java.security.PrivateKey caPrivateKey = encryptionService.decryptPrivateKey(
                encryptedData, iv, tag, Base64.getEncoder().encodeToString(userKey)
            );
            
            // Return the decrypted private key
            return caPrivateKey;
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt CA private key", e);
        }
    }

    /**
     * Parses a private key from PEM format.
     * 
     * @param pemData The PEM-encoded private key data
     * @return PrivateKey object
     * @throws RuntimeException if parsing fails
     */
    private PrivateKey parsePrivateKeyFromPEM(String pemData) {
        try {
            // Remove PEM headers and footers
            String cleanPem = pemData
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64
            byte[] derData = java.util.Base64.getDecoder().decode(cleanPem);
            
            // Create key factory
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            
            // Parse PKCS#8 or PKCS#1 format
            if (pemData.contains("BEGIN PRIVATE KEY")) {
                // PKCS#8 format
                java.security.spec.PKCS8EncodedKeySpec keySpec = 
                    new java.security.spec.PKCS8EncodedKeySpec(derData);
                return keyFactory.generatePrivate(keySpec);
            } else {
                // PKCS#1 format (RSA specific) - use PKCS8EncodedKeySpec for now
                java.security.spec.PKCS8EncodedKeySpec keySpec = 
                    new java.security.spec.PKCS8EncodedKeySpec(derData);
                return keyFactory.generatePrivate(keySpec);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse private key from PEM", e);
        }
    }

    /**
     * Gets the master encryption key for decrypting private keys.
     * 
     * @return Master key as byte array
     */
    private byte[] getMasterKey() {
        // This would get the master key from configuration or key management system
        // For now, return a placeholder key (in production, this should be secure)
        return "master-key-256-bits-long-for-testing".getBytes();
    }

    /**
     * Gets all revoked certificates for the web endpoint.
     * 
     * @return List of RevokedCertificateResponseDTO
     */
    public List<RevokedCertificateResponseDTO> getAllRevokedCertificates() {
        List<RevokedCertificate> revokedCertificates = revokedCertificateRepository.findAll();
        
        return revokedCertificates.stream()
                .map(this::convertToResponseDTO)
                .toList();
    }

    /**
     * Revokes a certificate.
     * 
     * @param request The revocation request
     * @param requesterId The ID of the user requesting revocation
     * @param requesterRole The role of the user requesting revocation
     */
    public void revokeCertificate(RevokeCertificateRequestDTO request, Long requesterId, Role requesterRole) {
        // Find the certificate
        Certificate certificate = certificateRepository.findBySerialNumber(request.getSerialNumber())
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        // Check if already revoked
        if (revokedCertificateRepository.existsByCertificate(certificate)) {
            throw new RuntimeException("Certificate is already revoked!");
        }


        // Admin can revoke any certificate
        // CA cant revoke any certificate
        if (requesterRole == Role.ADMIN) {
            // ADMIN can revoke any certificate
        } else if (requesterRole == Role.CA_USER) {
            // CA cant revoke any certificate
        }else if (requesterRole == Role.EE_USER){         
            //temporary just check if the certificate is owned by the requester
        } else {
            throw new RuntimeException("Invalid user role for certificate revocation!");
        }

        // Create revoked certificate record
        RevokedCertificate revokedCertificate = new RevokedCertificate();
        revokedCertificate.setCertificate(certificate);
        revokedCertificate.setIssuerCertificate(certificate.getIssuerCertificate());
        revokedCertificate.setRevokedBy(certificate.getSignedBy());
        revokedCertificate.setCertificateSerialNumber(certificate.getSerialNumber());
        revokedCertificate.setRevocationReason(request.getRevocationReason());

        // Update certificate status
        certificate.setStatus(CertificateStatus.REVOKED);
        certificate.setRevocationReason(request.getRevocationReason().name());
        certificate.setRevocationDate(LocalDateTime.now());

        // Save changes
        certificateRepository.save(certificate);
        revokedCertificateRepository.save(revokedCertificate);
    }

    /**
     * Gets the revocation file (CRL) for download.
     * 
     * @return Byte array containing the CRL file
     */
    public byte[] getRevocationFile() {
        // Find the main CA certificate (root certificate with ROOT type)
        List<Certificate> rootCertificates = certificateRepository.findByCertificateType(CertificateType.ROOT);
        if (rootCertificates.isEmpty()) {
            // If no root certificates exist, try to find any CA certificate that can sign
            List<Certificate> caCertificates = certificateRepository.findAll().stream()
                    .filter(cert -> cert.isCanSign())
                    .collect(java.util.stream.Collectors.toList());
            
            if (caCertificates.isEmpty()) {
                throw new RuntimeException("No CA certificates found! Please create a root CA certificate first.");
            }
            
            // Use the first CA certificate found
            Certificate mainCACertificate = caCertificates.get(0);
            return generateCRL(mainCACertificate);
        }
        
        // Use the first root certificate found
        Certificate mainCACertificate = rootCertificates.get(0);
        return generateCRL(mainCACertificate);
    }

    /**
     * Converts a RevokedCertificate entity to RevokedCertificateResponseDTO.
     */
    private RevokedCertificateResponseDTO convertToResponseDTO(RevokedCertificate revokedCertificate) {
        Certificate cert = revokedCertificate.getCertificate();
        
        RevokedCertificateResponseDTO dto = new RevokedCertificateResponseDTO();
        dto.setSerialNumber(cert.getSerialNumber());
        dto.setPrettySerialNumber(convertToHexDisplay(cert.getSerialNumber()));
        dto.setIssuedBy(cert.getIssuerDN());
        dto.setIssuedTo(cert.getSubjectDN());
        dto.setDecryptedCertificate(cert.getCertificateData());
        dto.setRevocationReason(revokedCertificate.getRevocationReason());
        
        return dto;
    }

    /**
     * Converts a decimal serial number to hex display format.
     */
    private String convertToHexDisplay(String serialNumber) {
        try {
            BigInteger decimal = new BigInteger(serialNumber);
            return decimal.toString(16).toUpperCase();
        } catch (NumberFormatException e) {
            return serialNumber; // Return as-is if not a valid number
        }
    }
}

