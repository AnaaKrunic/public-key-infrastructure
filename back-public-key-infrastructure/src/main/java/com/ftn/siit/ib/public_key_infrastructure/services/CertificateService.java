package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.*;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService.EncryptedData;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

/**
 * CertificateService manages the complete lifecycle of X.509 certificates in the PKI system.
 * 
 * This service handles:
 * - Creation of root, intermediate, and end-entity certificates
 * - Certificate retrieval and listing with role-based access control
 * - Certificate chain building and validation
 * - Certificate revocation
 * - Certificate export in various formats (PKCS12, PEM)
 * 
 * All operations enforce proper authorization and validation rules.
 */
@Service
@Transactional
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final ValidationService validationService;
    private final CertificateGeneratorService certificateGeneratorService;
    private final CertificateSignerService certificateSignerService;
    private final EncryptionService encryptionService;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final KeystoreService keystoreService;
    private final CRLService crlService;

    public CertificateService(
            CertificateRepository certificateRepository,
            ValidationService validationService,
            CertificateGeneratorService certificateGeneratorService,
            CertificateSignerService certificateSignerService,
            EncryptionService encryptionService,
            KeyPairGeneratorService keyPairGeneratorService,
            KeystoreService keystoreService,
            CRLService crlService) {
        this.certificateRepository = certificateRepository;
        this.validationService = validationService;
        this.certificateGeneratorService = certificateGeneratorService;
        this.certificateSignerService = certificateSignerService;
        this.encryptionService = encryptionService;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.keystoreService = keystoreService;
        this.crlService = crlService;
    }

    /**
     * Creates a self-signed root CA certificate.
     * 
     * Process:
     * 1. Generate RSA key pair with specified key size
     * 2. Build X500Name from subject DN fields
     * 3. Generate self-signed certificate with CA extensions
     * 4. Encrypt private key using AES-256-GCM with master key
     * 5. Save certificate entity to database with owner = admin
     * 
     * @param dto Certificate creation parameters (subject DN, validity, key size, etc.)
     * @param admin The admin user creating the certificate (must have ADMIN role)
     * @return CertificateDTO containing the created certificate details (without private key)
     * @throws IllegalArgumentException if dto or admin is null
     * @throws ValidationException if any field validation fails
     * @throws UnauthorizedException if admin does not have ADMIN role
     */
    public CertificateDTO createRootCertificate(CreateRootCertificateDTO dto, User admin) {
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (admin == null) {
            throw new IllegalArgumentException("Admin cannot be null");
        }
        if (admin.getRole() != Role.ADMIN) {
            throw new UnauthorizedException("Only ADMIN users can create root certificates");
        }

        // Generate key pair
        KeyPair keyPair = keyPairGeneratorService.generateKeyPair(dto.getKeySize());
        
        // Build subject DN
        X500Name subjectDN = certificateGeneratorService.buildX500Name(
            dto.getSubjectCN(),
            dto.getSubjectO(),
            dto.getSubjectOU(),
            dto.getSubjectL(),
            dto.getSubjectST(),
            dto.getSubjectC(),
            dto.getSubjectE()
        );

        // Generate certificate
        X509Certificate certificate = certificateGeneratorService.generateRootCertificate(
            keyPair,
            subjectDN,
            dto.getValidityDays(),
            dto.getKeyUsage(),
            dto.getBasicConstraints().getPathLength()
        );

        // Encrypt private key
        EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), "master-key");
        String encryptedPrivateKey = java.util.Base64.getEncoder().encodeToString(encryptedData.getEncryptedData());
        String iv = java.util.Base64.getEncoder().encodeToString(encryptedData.getIv());
        String tag = java.util.Base64.getEncoder().encodeToString(encryptedData.getTag());

        // Save to database
        Certificate certificateEntity = new Certificate();
        certificateEntity.setSerialNumber(certificate.getSerialNumber().toString());
        certificateEntity.setSubjectCN(dto.getSubjectCN());
        certificateEntity.setSubjectO(dto.getSubjectO());
        certificateEntity.setSubjectOU(dto.getSubjectOU());
        certificateEntity.setSubjectL(dto.getSubjectL());
        certificateEntity.setSubjectST(dto.getSubjectST());
        certificateEntity.setSubjectC(dto.getSubjectC());
        certificateEntity.setSubjectE(dto.getSubjectE());
        certificateEntity.setSubjectDN(subjectDN.toString());
        certificateEntity.setIssuerCN(dto.getSubjectCN()); // Self-signed
        certificateEntity.setIssuerO(dto.getSubjectO());
        certificateEntity.setIssuerOU(dto.getSubjectOU());
        certificateEntity.setIssuerL(dto.getSubjectL());
        certificateEntity.setIssuerST(dto.getSubjectST());
        certificateEntity.setIssuerC(dto.getSubjectC());
        certificateEntity.setIssuerE(dto.getSubjectE());
        certificateEntity.setIssuerDN(subjectDN.toString()); // Self-signed
        certificateEntity.setValidFrom(LocalDateTime.now());
        certificateEntity.setValidTo(LocalDateTime.now().plusDays(dto.getValidityDays()));
        certificateEntity.setCertificateType(CertificateType.ROOT);
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setPublicKey(keystoreService.exportPublicKeyAsPEM(keyPair.getPublic()));
        certificateEntity.setEncryptedPrivateKey(encryptedPrivateKey);
        certificateEntity.setEncryptionIV(iv);
        certificateEntity.setEncryptionTag(tag);
        certificateEntity.setCertificateData(keystoreService.exportCertificateAsPEM(certificate));
        certificateEntity.setKeyUsage(String.join(",", dto.getKeyUsage()));
        certificateEntity.setOwner(admin);

        certificateRepository.save(certificateEntity);

        return convertToDTO(certificateEntity);
    }

    /**
     * Creates an intermediate CA certificate signed by a root or another intermediate CA.
     * 
     * Process:
     * 1. Validate issuer certificate is a valid CA using ValidationService
     * 2. Generate key pair for the new intermediate CA
     * 3. Build subject and issuer X500Names
     * 4. Decrypt issuer's private key for signing
     * 5. Generate intermediate certificate signed by issuer
     * 6. Encrypt new private key
     * 7. Save with issuerCertificate reference
     * 
     * @param dto Certificate creation parameters including issuer serial number
     * @param admin The admin user creating the certificate (must have ADMIN role)
     * @return CertificateDTO containing the created certificate details
     * @throws IllegalArgumentException if dto or admin is null
     * @throws ValidationException if validation fails
     * @throws UnauthorizedException if admin does not have ADMIN role
     * @throws NotFoundException if issuer certificate not found
     */
    public CertificateDTO createIntermediateCertificate(CreateIntermediateCertificateDTO dto, User admin) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Creates an end-entity certificate for a user or server.
     * 
     * Process:
     * 1. Validate request using ValidationService
     * 2. If templateId provided, validate against template constraints
     * 3. Generate key pair for the end entity
     * 4. Build certificate with appropriate extensions (Key Usage, Extended Key Usage, SANs)
     * 5. Decrypt issuer's private key and sign the certificate
     * 6. Encrypt new private key
     * 7. Save with owner = requester
     * 
     * Authorization:
     * - ADMIN can create certificates with any issuer
     * - CA_USER can only create certificates using their own CA certificates
     * - REGULAR_USER cannot create certificates directly (must use CSR workflow)
     * 
     * @param dto Certificate creation parameters
     * @param requester The user requesting the certificate
     * @return CertificateDTO containing the created certificate details
     * @throws IllegalArgumentException if dto or requester is null
     * @throws ValidationException if validation fails
     * @throws UnauthorizedException if requester lacks permission
     * @throws TemplateConstraintViolationException if template constraints are violated
     */
    public CertificateDTO createEndEntityCertificate(CreateEndEntityCertificateDTO dto, User requester) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Retrieves a certificate by its serial number with role-based access control.
     * 
     * Access rules:
     * - ADMIN: Can view any certificate
     * - CA_USER: Can view certificates in their CA chain (issued by them or their CAs)
     * - REGULAR_USER: Can only view their own certificates
     * 
     * @param serialNumber The certificate serial number (hex string)
     * @param requester The user requesting the certificate
     * @return CertificateDTO containing certificate details
     * @throws IllegalArgumentException if serialNumber or requester is null
     * @throws NotFoundException if certificate not found
     * @throws ForbiddenException if requester does not have access
     */
    public CertificateDTO getCertificateBySerialNumber(String serialNumber, User requester) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Lists certificates with optional filtering and role-based access control.
     * 
     * Filtering:
     * - By certificate type (ROOT, INTERMEDIATE, END_ENTITY)
     * - By status (VALID, REVOKED)
     * - Pagination support
     * 
     * Access rules:
     * - ADMIN: Sees all certificates
     * - CA_USER: Sees certificates in their CA chain
     * - REGULAR_USER: Sees only their own certificates
     * 
     * @param type Optional certificate type filter
     * @param status Optional certificate status filter
     * @param pageable Pagination parameters
     * @param requester The user requesting the list
     * @return Page of CertificateDTO objects
     * @throws IllegalArgumentException if requester is null
     */
    public Page<CertificateDTO> listCertificates(CertificateType type, CertificateStatus status, 
                                                   Pageable pageable, User requester) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Builds and validates the complete certificate chain from a certificate to the root CA.
     * 
     * The chain is built by following issuerCertificate references and validated
     * using ValidationService to ensure cryptographic integrity.
     * 
     * @param serialNumber The serial number of the certificate
     * @return CertificateChainDTO containing the ordered chain (end-entity to root)
     * @throws IllegalArgumentException if serialNumber is null
     * @throws NotFoundException if certificate not found
     * @throws InvalidCertificateChainException if chain validation fails
     */
    public CertificateChainDTO getCertificateChain(String serialNumber) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Revokes a certificate and triggers CRL regeneration.
     * 
     * Process:
     * 1. Validate revocation permission using ValidationService
     * 2. Update certificate status to REVOKED
     * 3. Set revocationReason and revocationDate
     * 4. Trigger CRL regeneration for the issuer CA
     * 
     * Revocation reasons (RFC 5280):
     * 0 = unspecified, 1 = keyCompromise, 2 = cACompromise, 3 = affiliationChanged,
     * 4 = superseded, 5 = cessationOfOperation, 6 = certificateHold, 8 = removeFromCRL,
     * 9 = privilegeWithdrawn, 10 = aACompromise
     * 
     * @param serialNumber The serial number of the certificate to revoke
     * @param dto Revocation details (reason, etc.)
     * @param requester The user requesting the revocation
     * @return CertificateDTO of the revoked certificate
     * @throws IllegalArgumentException if serialNumber, dto, or requester is null
     * @throws NotFoundException if certificate not found
     * @throws UnauthorizedException if requester lacks permission
     * @throws IllegalStateException if certificate is already revoked
     */
    public CertificateDTO revokeCertificate(String serialNumber, RevokeCertificateDTO dto, User requester) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Exports a certificate with its private key in the specified format.
     * 
     * Supported formats:
     * - PKCS12: Encrypted keystore containing certificate chain and private key
     * - PEM: PEM-encoded certificate chain and private key
     * 
     * Security:
     * - Only the certificate owner or ADMIN can download with private key
     * - Private key is decrypted from database using master key
     * - For PKCS12, the keystore is encrypted with the provided password
     * 
     * @param serialNumber The serial number of the certificate
     * @param format Export format ("PKCS12" or "PEM")
     * @param password Password for PKCS12 keystore (required for PKCS12, ignored for PEM)
     * @param requester The user requesting the download
     * @return Byte array containing the exported certificate data
     * @throws IllegalArgumentException if serialNumber, format, or requester is null
     * @throws NotFoundException if certificate not found
     * @throws ForbiddenException if requester is not the owner and not ADMIN
     * @throws ValidationException if password is missing for PKCS12 format
     */
    public byte[] downloadCertificate(String serialNumber, String format, String password, User requester) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Converts a Certificate entity to a CertificateDTO for API responses.
     * 
     * Note: Private key is never included in the DTO for security reasons.
     * 
     * @param certificate The certificate entity
     * @return CertificateDTO containing public certificate information
     */
    private CertificateDTO convertToDTO(Certificate certificate) {
        if (certificate == null) {
            return null;
        }

        CertificateDTO dto = new CertificateDTO();
        dto.setId(certificate.getId());
        dto.setSerialNumber(certificate.getSerialNumber());
        dto.setSubjectCN(certificate.getSubjectCN());
        dto.setSubjectO(certificate.getSubjectO());
        dto.setSubjectOU(certificate.getSubjectOU());
        dto.setSubjectL(certificate.getSubjectL());
        dto.setSubjectST(certificate.getSubjectST());
        dto.setSubjectC(certificate.getSubjectC());
        dto.setSubjectE(certificate.getSubjectE());
        dto.setSubjectDN(certificate.getSubjectDN());
        dto.setIssuerCN(certificate.getIssuerCN());
        dto.setIssuerO(certificate.getIssuerO());
        dto.setIssuerOU(certificate.getIssuerOU());
        dto.setIssuerL(certificate.getIssuerL());
        dto.setIssuerST(certificate.getIssuerST());
        dto.setIssuerC(certificate.getIssuerC());
        dto.setIssuerE(certificate.getIssuerE());
        dto.setIssuerDN(certificate.getIssuerDN());
        dto.setValidFrom(certificate.getValidFrom());
        dto.setValidTo(certificate.getValidTo());
        dto.setCertificateType(certificate.getCertificateType());
        dto.setStatus(certificate.getStatus());
        dto.setKeyUsage(certificate.getKeyUsage());
        dto.setExtendedKeyUsage(certificate.getExtendedKeyUsage());
        dto.setSubjectAlternativeNames(certificate.getSubjectAlternativeNames());
        dto.setRevocationReason(certificate.getRevocationReason());
        dto.setRevocationDate(certificate.getRevocationDate());
        dto.setCreatedAt(certificate.getCreatedAt());
        
        if (certificate.getOwner() != null) {
            CertificateDTO.UserDTO ownerDTO = new CertificateDTO.UserDTO();
            ownerDTO.setId(certificate.getOwner().getId());
            ownerDTO.setEmail(certificate.getOwner().getEmail());
            ownerDTO.setFirstName(certificate.getOwner().getFirstName());
            ownerDTO.setLastName(certificate.getOwner().getLastName());
            dto.setOwner(ownerDTO);
        }
        
        if (certificate.getIssuerCertificate() != null) {
            // For issuer certificate, we only need basic info to avoid circular references
            CertificateDTO issuerDTO = new CertificateDTO();
            issuerDTO.setId(certificate.getIssuerCertificate().getId());
            issuerDTO.setSerialNumber(certificate.getIssuerCertificate().getSerialNumber());
            issuerDTO.setSubjectCN(certificate.getIssuerCertificate().getSubjectCN());
            issuerDTO.setSubjectDN(certificate.getIssuerCertificate().getSubjectDN());
            issuerDTO.setCertificateType(certificate.getIssuerCertificate().getCertificateType());
            dto.setIssuerCertificate(issuerDTO);
        }
        
        return dto;
    }

    /**
     * Checks if a user has access to view a certificate based on their role.
     * 
     * @param certificate The certificate to check
     * @param requester The user requesting access
     * @return true if the user has access, false otherwise
     */
    private boolean hasAccessToCertificate(Certificate certificate, User requester) {
        if (certificate == null || requester == null) {
            return false;
        }

        // Admin can access all certificates
        if (requester.getRole() == Role.ADMIN) {
            return true;
        }

        // CA_USER can access certificates they issued or own
        if (requester.getRole() == Role.CA_USER) {
            return certificate.getOwner() != null && certificate.getOwner().getId().equals(requester.getId()) ||
                   certificate.getIssuerCertificate() != null && 
                   certificate.getIssuerCertificate().getOwner() != null &&
                   certificate.getIssuerCertificate().getOwner().getId().equals(requester.getId());
        }

        // REGULAR_USER can only access their own certificates
        if (requester.getRole() == Role.REGULAR_USER) {
            return certificate.getOwner() != null && certificate.getOwner().getId().equals(requester.getId());
        }

        return false;
    }

}

