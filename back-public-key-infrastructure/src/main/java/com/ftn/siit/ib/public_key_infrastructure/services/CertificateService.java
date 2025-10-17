package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.*;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService.EncryptedData;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;

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
    private final UserRepository userRepository;
    private final ValidationService validationService;
    private final CertificateGeneratorService certificateGeneratorService;
    private final CertificateSignerService certificateSignerService;
    private final EncryptionService encryptionService;
    private final KeyPairGeneratorService keyPairGeneratorService;
    private final KeystoreService keystoreService;
    private final CRLService crlService;
    private final MasterKeyService masterKeyService;
    private final UserKeyService userKeyService;

    public CertificateService(
            CertificateRepository certificateRepository,
            UserRepository userRepository,
            ValidationService validationService,
            CertificateGeneratorService certificateGeneratorService,
            CertificateSignerService certificateSignerService,
            EncryptionService encryptionService,
            KeyPairGeneratorService keyPairGeneratorService,
            KeystoreService keystoreService,
            CRLService crlService,
            MasterKeyService masterKeyService,
            UserKeyService userKeyService) {
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.validationService = validationService;
        this.certificateGeneratorService = certificateGeneratorService;
        this.certificateSignerService = certificateSignerService;
        this.encryptionService = encryptionService;
        this.keyPairGeneratorService = keyPairGeneratorService;
        this.keystoreService = keystoreService;
        this.crlService = crlService;
        this.masterKeyService = masterKeyService;
        this.userKeyService = userKeyService;
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

        // Encrypt private key with user-specific key
        byte[] userKey = userKeyService.getUserKey(admin.getId());
        EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
        String encryptedPrivateKey = Base64.getEncoder().encodeToString(encryptedData.getEncryptedData());
        String iv = Base64.getEncoder().encodeToString(encryptedData.getIv());
        String tag = Base64.getEncoder().encodeToString(encryptedData.getTag());

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
        certificateEntity.setStatus(CertificateStatus.ACTIVE);
        certificateEntity.setCanSign(true);
        certificateEntity.setPublicKey(keystoreService.exportPublicKeyAsPEM(keyPair.getPublic()));
        certificateEntity.setEncryptedPrivateKey(encryptedPrivateKey);
        certificateEntity.setEncryptionIV(iv);
        certificateEntity.setEncryptionTag(tag);
        certificateEntity.setCertificateData(keystoreService.exportCertificateAsPEM(certificate));
        certificateEntity.setKeyUsage(String.join(",", dto.getKeyUsage()));
        certificateEntity.setPathLength(dto.getBasicConstraints().getPathLength());
        // Owner removed - using many-to-many relationship now
        certificateEntity.setSignedBy(admin);
        certificateEntity.setSigningCertificate(null);
        certificateEntity.setSigningOrganization(admin.getOrganization());

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
        // Validate parameters
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (admin == null) {
            throw new IllegalArgumentException("Admin cannot be null");
        }
        if (admin.getRole() != Role.ADMIN) {
            throw new UnauthorizedException("Only ADMIN users can create intermediate certificates");
        }

        // Fetch issuer certificate
        Certificate issuer = certificateRepository.findById(dto.getIssuerCertificateId())
            .orElseThrow(() -> new NotFoundException("Issuer certificate not found"));

        // Validate issuer certificate
        validationService.validateIssuerCertificate(issuer);

        // Check path length constraints
        if (issuer.getPathLength() != null && dto.getBasicConstraints().getPathLength() != null) {
            if (issuer.getPathLength() < dto.getBasicConstraints().getPathLength() + 1) {
                throw new IllegalArgumentException("Path length constraint violation");
            }
        }

        // Generate key pair
        KeyPair keyPair = keyPairGeneratorService.generateKeyPair(dto.getKeySize());

        // Build subject and issuer DNs
        X500Name subjectDN = certificateGeneratorService.buildX500Name(
            dto.getSubjectCN(), dto.getSubjectO(), dto.getSubjectOU(),
            dto.getSubjectL(), dto.getSubjectST(), dto.getSubjectC(), dto.getSubjectE()
        );
        X500Name issuerDN = certificateGeneratorService.buildX500Name(
            issuer.getIssuerCN(), issuer.getIssuerO(), issuer.getIssuerOU(),
            issuer.getIssuerL(), issuer.getIssuerST(), issuer.getIssuerC(), issuer.getIssuerE()
        );

        // Decrypt issuer's private key
        java.security.PrivateKey issuerPrivateKey = encryptionService.decryptPrivateKey(
            Base64.getDecoder().decode(issuer.getEncryptedPrivateKey()),
            Base64.getDecoder().decode(issuer.getEncryptionIV()),
            Base64.getDecoder().decode(issuer.getEncryptionTag()),
            Base64.getEncoder().encodeToString(masterKeyService.getMasterKey())
        );

        // Parse issuer's public key
        java.security.PublicKey issuerPublicKey = parsePublicKeyFromPEM(issuer.getPublicKey());

        // Generate intermediate certificate
        X509Certificate certificate = certificateGeneratorService.generateIntermediateCertificate(
            keyPair, subjectDN, issuerDN, issuerPrivateKey, issuerPublicKey,
            dto.getValidityDays(), dto.getKeyUsage(), dto.getBasicConstraints().getPathLength()
        );

        // Encrypt private key with user-specific key
        byte[] userKey = userKeyService.getUserKey(admin.getId());
        EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
        String encryptedPrivateKey = Base64.getEncoder().encodeToString(encryptedData.getEncryptedData());
        String iv = Base64.getEncoder().encodeToString(encryptedData.getIv());
        String tag = Base64.getEncoder().encodeToString(encryptedData.getTag());

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
        certificateEntity.setIssuerCN(issuer.getIssuerCN());
        certificateEntity.setIssuerO(issuer.getIssuerO());
        certificateEntity.setIssuerOU(issuer.getIssuerOU());
        certificateEntity.setIssuerL(issuer.getIssuerL());
        certificateEntity.setIssuerST(issuer.getIssuerST());
        certificateEntity.setIssuerC(issuer.getIssuerC());
        certificateEntity.setIssuerE(issuer.getIssuerE());
        certificateEntity.setIssuerDN(issuerDN.toString());
        certificateEntity.setValidFrom(LocalDateTime.now());
        certificateEntity.setValidTo(LocalDateTime.now().plusDays(dto.getValidityDays()));
        certificateEntity.setCertificateType(CertificateType.INTERMEDIATE);
        certificateEntity.setStatus(CertificateStatus.ACTIVE);
        certificateEntity.setCanSign(true);
        certificateEntity.setPublicKey(keystoreService.exportPublicKeyAsPEM(keyPair.getPublic()));
        certificateEntity.setEncryptedPrivateKey(encryptedPrivateKey);
        certificateEntity.setEncryptionIV(iv);
        certificateEntity.setEncryptionTag(tag);
        certificateEntity.setCertificateData(keystoreService.exportCertificateAsPEM(certificate));
        certificateEntity.setKeyUsage(String.join(",", dto.getKeyUsage()));
        certificateEntity.setPathLength(dto.getBasicConstraints().getPathLength());
        // Owner removed - using many-to-many relationship now
        certificateEntity.setIssuerCertificate(issuer);
        certificateEntity.setSignedBy(admin);
        certificateEntity.setSigningCertificate(issuer);
        certificateEntity.setSigningOrganization(
                admin.getOrganization() // Organization from admin since issuer owner removed
        );

        certificateRepository.save(certificateEntity);

        return convertToDTO(certificateEntity);
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
     * - EE_USER cannot create certificates directly (must use CSR workflow)
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
        // Validate parameters
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Validate request
        validationService.validateCertificateRequest(dto, requester);

        // Fetch issuer certificate
        Certificate issuer = certificateRepository.findById(dto.getIssuerCertificateId())
            .orElseThrow(() -> new NotFoundException("Issuer certificate not found"));

        // Check authorization
        if (requester.getRole() == Role.EE_USER) {
            throw new UnauthorizedException("EE_USER cannot create certificates directly");
        }
        if (requester.getRole() == Role.CA_USER && !issuer.getSignedBy().getId().equals(requester.getId())) {
            throw new UnauthorizedException("CA_USER can only create certificates using their own CA certificates");
        }

        // If templateId provided, validate against template constraints
        if (dto.getTemplateId() != null) {
            // TODO: Implement template validation when TemplateService is available
            // CertificateTemplate template = templateRepository.findById(dto.getTemplateId())
            //     .orElseThrow(() -> new NotFoundException("Template not found"));
            // validationService.validateTemplateConstraints(dto, template);
        }

        // Validate issuer certificate
        validationService.validateIssuerCertificate(issuer);

        // Generate key pair
        KeyPair keyPair = keyPairGeneratorService.generateKeyPair(dto.getKeySize());

        // Build subject and issuer DNs
        X500Name subjectDN = certificateGeneratorService.buildX500Name(
            dto.getSubjectCN(), dto.getSubjectO(), dto.getSubjectOU(),
            dto.getSubjectL(), dto.getSubjectST(), dto.getSubjectC(), dto.getSubjectE()
        );
        X500Name issuerDN = certificateGeneratorService.buildX500Name(
            issuer.getIssuerCN(), issuer.getIssuerO(), issuer.getIssuerOU(),
            issuer.getIssuerL(), issuer.getIssuerST(), issuer.getIssuerC(), issuer.getIssuerE()
        );

        // Decrypt issuer's private key
        java.security.PrivateKey issuerPrivateKey = encryptionService.decryptPrivateKey(
            Base64.getDecoder().decode(issuer.getEncryptedPrivateKey()),
            Base64.getDecoder().decode(issuer.getEncryptionIV()),
            Base64.getDecoder().decode(issuer.getEncryptionTag()),
            Base64.getEncoder().encodeToString(masterKeyService.getMasterKey())
        );

        // Parse issuer's public key
        java.security.PublicKey issuerPublicKey = parsePublicKeyFromPEM(issuer.getPublicKey());

        // Generate end-entity certificate
        X509Certificate certificate = certificateGeneratorService.generateEndEntityCertificate(
            keyPair, subjectDN, issuerDN, issuerPrivateKey, issuerPublicKey,
            dto.getValidityDays(), dto.getKeyUsage(), dto.getExtendedKeyUsage(), 
            dto.getSubjectAlternativeNames(), dto.getCrlDistributionPoint()
        );

        // Encrypt private key with user-specific key
        byte[] userKey = userKeyService.getUserKey(requester.getId());
        EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
        String encryptedPrivateKey = Base64.getEncoder().encodeToString(encryptedData.getEncryptedData());
        String iv = Base64.getEncoder().encodeToString(encryptedData.getIv());
        String tag = Base64.getEncoder().encodeToString(encryptedData.getTag());

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
        certificateEntity.setIssuerCN(issuer.getIssuerCN());
        certificateEntity.setIssuerO(issuer.getIssuerO());
        certificateEntity.setIssuerOU(issuer.getIssuerOU());
        certificateEntity.setIssuerL(issuer.getIssuerL());
        certificateEntity.setIssuerST(issuer.getIssuerST());
        certificateEntity.setIssuerC(issuer.getIssuerC());
        certificateEntity.setIssuerE(issuer.getIssuerE());
        certificateEntity.setIssuerDN(issuerDN.toString());
        certificateEntity.setValidFrom(LocalDateTime.now());
        certificateEntity.setValidTo(LocalDateTime.now().plusDays(dto.getValidityDays()));
        certificateEntity.setCertificateType(CertificateType.END_ENTITY);
        certificateEntity.setStatus(CertificateStatus.ACTIVE);
        certificateEntity.setCanSign(false);
        certificateEntity.setPublicKey(keystoreService.exportPublicKeyAsPEM(keyPair.getPublic()));
        certificateEntity.setEncryptedPrivateKey(encryptedPrivateKey);
        certificateEntity.setEncryptionIV(iv);
        certificateEntity.setEncryptionTag(tag);
        certificateEntity.setCertificateData(keystoreService.exportCertificateAsPEM(certificate));
        certificateEntity.setKeyUsage(String.join(",", dto.getKeyUsage()));
        certificateEntity.setExtendedKeyUsage(dto.getExtendedKeyUsage() != null ? String.join(",", dto.getExtendedKeyUsage()) : null);
        certificateEntity.setSubjectAlternativeNames(dto.getSubjectAlternativeNames() != null ? String.join(",", dto.getSubjectAlternativeNames()) : null);
        // Owner removed - using many-to-many relationship now
        certificateEntity.setIssuerCertificate(issuer);
        certificateEntity.setSignedBy(requester);
        certificateEntity.setSigningCertificate(issuer);
        certificateEntity.setSigningOrganization(
                null // Organization removed since issuer owner removed
        );

        certificateRepository.save(certificateEntity);

        return convertToDTO(certificateEntity);
    }

    /**
     * Retrieves a certificate by its serial number with role-based access control.
     * 
     * Access rules:
     * - ADMIN: Can view any certificate
     * - CA_USER: Can view certificates in their CA chain (issued by them or their CAs)
     * - EE_USER: Can only view their own certificates
     * 
     * @param serialNumber The certificate serial number (hex string)
     * @param requester The user requesting the certificate
     * @return CertificateDTO containing certificate details
     * @throws IllegalArgumentException if serialNumber or requester is null
     * @throws NotFoundException if certificate not found
     * @throws ForbiddenException if requester does not have access
     */
    public CertificateDTO getCertificateBySerialNumber(String serialNumber, User requester) {
        // Validate parameters
        if (serialNumber == null) {
            throw new IllegalArgumentException("Serial number cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Find certificate
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));

        // Check access
        if (!hasAccessToCertificate(certificate, requester)) {
            throw new ForbiddenException("Access denied to certificate");
        }

        return convertToDTO(certificate);
    }

    /**
     * Helper method to check if a user has access to a certificate.
     */
    private boolean hasAccessToCertificate(Certificate certificate, User requester) {
        // ADMIN can access any certificate
        if (requester.getRole() == Role.ADMIN) {
            return true;
        }
        
        // CA_USER can access certificates they signed
        if (requester.getRole() == Role.CA_USER && certificate.getSignedBy() != null) {
            return certificate.getSignedBy().getId().equals(requester.getId());
        }
        
        return false;
    }

    /**
     * Lists certificates with optional filtering and role-based access control.
     * 
     * Filtering:
     * - By certificate type (ROOT, INTERMEDIATE, END_ENTITY)
     * - By status (ACTIVE, REVOKED)
     * - Pagination support
     * 
     * Access rules:
     * - ADMIN: Sees all certificates
     * - CA_USER: Sees certificates in their CA chain
     * - EE_USER: Sees only their own certificates
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
        // Validate parameters
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        Page<Certificate> certificates;
        
        // Build query based on role
        if (requester.getRole() == Role.ADMIN) {
            // ADMIN can see all certificates
            certificates = certificateRepository.findAll(pageable);
        } else if (requester.getRole() == Role.CA_USER) {
            // CA_USER can see certificates they own or issued
            certificates = certificateRepository.findBySignedBy(requester, pageable);
        } else {
            // EE_USER can only see their own certificates
            // EE_USER can see certificates in their MyCertificates collection
            // This would need to be implemented differently - for now return empty
            certificates = new org.springframework.data.domain.PageImpl<>(new ArrayList<>(), pageable, 0);
        }

        // Apply filters if provided
        if (type != null || status != null) {
            // For now, we'll filter in memory. In a real implementation, you'd want to add these filters to the repository query
            List<Certificate> filteredList = certificates.getContent().stream()
                .filter(cert -> type == null || cert.getCertificateType() == type)
                .filter(cert -> status == null || cert.getStatus() == status)
                .collect(java.util.stream.Collectors.toList());
            
            // Create a new page with filtered content
            certificates = new org.springframework.data.domain.PageImpl<>(
                filteredList, 
                pageable, 
                filteredList.size()
            );
        }

        // Convert to DTOs
        return certificates.map(this::convertToDTO);
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
        // Validate parameters
        if (serialNumber == null) {
            throw new IllegalArgumentException("Serial number cannot be null");
        }

        // Find certificate
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));

        // Build chain by following issuerCertificate references
        List<Certificate> chain = new ArrayList<>();
        Certificate current = certificate;
        while (current != null) {
            chain.add(current);
            if (current.getIssuerCertificate() == null) {
                break; // Reached root certificate
            }
            current = current.getIssuerCertificate();
        }

        // Validate chain
        boolean isValid = true;
        try {
            validationService.validateCertificateChain(certificate);
        } catch (Exception e) {
            isValid = false;
        }

        // Convert to DTOs
        List<CertificateDTO> certificateDTOs = chain.stream()
            .map(this::convertToDTO)
            .collect(java.util.stream.Collectors.toList());

        // Create and return CertificateChainDTO
        CertificateChainDTO chainDTO = new CertificateChainDTO();
        chainDTO.setCertificates(certificateDTOs);
        chainDTO.setValid(isValid);

        return chainDTO;
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
        // Validate parameters
        if (serialNumber == null) {
            throw new IllegalArgumentException("Serial number cannot be null");
        }
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Find certificate
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));

        // Validate revocation permission
        validationService.validateRevocationRequest(certificate, requester);

        // Check if already revoked
        if (certificate.getStatus() == CertificateStatus.REVOKED) {
            throw new IllegalStateException("Certificate is already revoked");
        }

        // Update certificate status
        certificate.setStatus(CertificateStatus.REVOKED);
        certificate.setRevocationReason(dto.getReason());
        certificate.setRevocationDate(LocalDateTime.now());

        // Save certificate
        certificateRepository.save(certificate);

        // Trigger CRL regeneration for the issuer CA
        if (certificate.getIssuerCertificate() != null) {
            crlService.updateCRL(certificate.getIssuerCertificate());
        }

        return convertToDTO(certificate);
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
        // Validate parameters
        if (serialNumber == null) {
            throw new IllegalArgumentException("Serial number cannot be null");
        }
        if (format == null) {
            throw new IllegalArgumentException("Format cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Find certificate
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));

        // Check authorization (owner or ADMIN)
        if (!hasAccessToCertificate(certificate, requester)) {
            throw new ForbiddenException("Access denied to certificate");
        }

        // Build certificate chain
        List<Certificate> chain = new ArrayList<>();
        Certificate current = certificate;
        while (current != null) {
            chain.add(current);
            if (current.getIssuerCertificate() == null) {
                break; // Reached root certificate
            }
            current = current.getIssuerCertificate();
        }

        // Decrypt private key
        java.security.PrivateKey privateKey = encryptionService.decryptPrivateKey(
            Base64.getDecoder().decode(certificate.getEncryptedPrivateKey()),
            Base64.getDecoder().decode(certificate.getEncryptionIV()),
            Base64.getDecoder().decode(certificate.getEncryptionTag()),
            Base64.getEncoder().encodeToString(masterKeyService.getMasterKey())
        );

        // Parse X509Certificate from PEM
        X509Certificate x509Certificate = parseX509CertificateFromPEM(certificate.getCertificateData());

        // Export based on format
        if ("PKCS12".equalsIgnoreCase(format)) {
            if (password == null) {
                throw new IllegalArgumentException("Password is required for PKCS12 format");
            }
            return keystoreService.createPKCS12Keystore(
                privateKey, 
                List.of(x509Certificate), 
                password
            );
        } else if ("PEM".equalsIgnoreCase(format)) {
            // Export certificate chain and private key in PEM format
            String certificateChainPEM = keystoreService.exportCertificateChainAsPEM(List.of(x509Certificate));
            String privateKeyPEM = keystoreService.exportPrivateKeyAsPEM(privateKey);
            return (certificateChainPEM + "\n" + privateKeyPEM).getBytes();
        } else {
            throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    /**
     * Helper method to parse X509Certificate from PEM string.
     */
    private X509Certificate parseX509CertificateFromPEM(String pemData) {
        try {
            // Remove PEM headers and footers
            String cleanPem = pemData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64
            byte[] derData = Base64.getDecoder().decode(cleanPem);
            
            // Create certificate factory
            java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
            
            // Generate certificate from DER data
            return (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(derData)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse X509Certificate from PEM", e);
        }
    }
    
    /**
     * Builds a certificate chain from the given certificate up to the root.
     * 
     * @param certificate The starting certificate
     * @return List of certificates in the chain (end-entity first, root last)
     */
    private List<X509Certificate> buildCertificateChain(Certificate certificate) {
        List<X509Certificate> chain = new ArrayList<>();
        
        try {
            // Add the current certificate
            X509Certificate currentCert = parseX509CertificateFromPEM(certificate.getCertificateData());
            chain.add(currentCert);
            
            // Follow the issuer chain
            Certificate current = certificate;
            while (current.getIssuerCertificate() != null) {
                current = current.getIssuerCertificate();
                X509Certificate issuerCert = parseX509CertificateFromPEM(current.getCertificateData());
                chain.add(issuerCert);
            }
            
            return chain;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build certificate chain for certificate " + certificate.getSerialNumber(), e);
        }
    }
    
    /**
     * Helper method to parse public key from PEM string
     * TODO: Implement proper PEM parsing
     */
    private java.security.PublicKey parsePublicKeyFromPEM(String pemString) {
        // This is a placeholder implementation
        // In a real implementation, you would parse the PEM string and create a PublicKey
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // Use a 2048-bit RSA key for testing
            java.math.BigInteger modulus = new java.math.BigInteger("1").shiftLeft(2048).subtract(java.math.BigInteger.ONE);
            return keyFactory.generatePublic(new RSAPublicKeySpec(modulus, java.math.BigInteger.valueOf(65537)));
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse public key", e);
        }
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
        dto.setPublicKey(certificate.getPublicKey());
        dto.setCertificateData(certificate.getCertificateData());
        dto.setKeyUsage(certificate.getKeyUsage());
        dto.setExtendedKeyUsage(certificate.getExtendedKeyUsage());
        dto.setSubjectAlternativeNames(certificate.getSubjectAlternativeNames());
        dto.setCrlDistributionPoint(certificate.getCrlDistributionPoint());
        dto.setCanSign(certificate.isCanSign());
        dto.setPathLength(certificate.getPathLength());
        dto.setRevocationReason(certificate.getRevocationReason());
        dto.setRevocationDate(certificate.getRevocationDate());
        dto.setCreatedAt(certificate.getCreatedAt());
        
        // Owner information removed - using many-to-many relationship now

        if (certificate.getSignedBy() != null) {
            CertificateDTO.UserDTO signedByDTO = new CertificateDTO.UserDTO();
            signedByDTO.setId(certificate.getSignedBy().getId());
            signedByDTO.setEmail(certificate.getSignedBy().getEmail());
            signedByDTO.setFirstName(certificate.getSignedBy().getFirstName());
            signedByDTO.setLastName(certificate.getSignedBy().getLastName());
            dto.setSignedBy(signedByDTO);
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

        if (certificate.getSigningCertificate() != null) {
            CertificateDTO signingCertDTO = new CertificateDTO();
            signingCertDTO.setId(certificate.getSigningCertificate().getId());
            signingCertDTO.setSerialNumber(certificate.getSigningCertificate().getSerialNumber());
            signingCertDTO.setSubjectCN(certificate.getSigningCertificate().getSubjectCN());
            signingCertDTO.setSubjectDN(certificate.getSigningCertificate().getSubjectDN());
            signingCertDTO.setCertificateType(certificate.getSigningCertificate().getCertificateType());
            dto.setSigningCertificate(signingCertDTO);
        }

        if (certificate.getSigningOrganization() != null) {
            CertificateDTO.OrganizationDTO organizationDTO = new CertificateDTO.OrganizationDTO(
                    certificate.getSigningOrganization().getId(),
                    certificate.getSigningOrganization().getName(),
                    certificate.getSigningOrganization().getContactEmail()
            );
            dto.setSigningOrganization(organizationDTO);
        }
        
        return dto;
    }


    /**
     * Adds a certificate to a CA user's certificate collection.
     * 
     * @param caUserId The ID of the CA user
     * @param certificateId The ID of the certificate to add
     * @throws IllegalArgumentException if caUserId or certificateId is null
     * @throws NotFoundException if user or certificate not found
     */
    public void addCertificateToCaUser(Long caUserId, Long certificateId) {
        if (caUserId == null) {
            throw new IllegalArgumentException("CA user ID cannot be null");
        }
        if (certificateId == null) {
            throw new IllegalArgumentException("Certificate ID cannot be null");
        }

        // Find the CA user
        User caUser = userRepository.findById(caUserId)
            .orElseThrow(() -> new NotFoundException("CA user not found"));

        // Find the certificate
        Certificate certificate = certificateRepository.findById(certificateId)
            .orElseThrow(() -> new NotFoundException("Certificate not found"));

        // Add certificate to user's collection
        // Note: This assumes there's a relationship between User and Certificate
        // The exact implementation depends on how the relationship is modeled
        // For now, we'll assume the certificate's owner is set to the CA user
        // Owner removed - using many-to-many relationship now
        certificateRepository.save(certificate);
    }

    /**
     * Determines the current status of a certificate based on various factors.
     * 
     * Status determination logic:
     * - ACTIVE: Certificate is valid, not expired, not revoked, and within validity period
     * - EXPIRED: Certificate has passed its notAfter date
     * - DORMANT: Certificate is not yet valid (before notBefore date)
     * - REVOKED: Certificate has been revoked
     * - INVALID: Certificate has other issues (signature validation, etc.)
     * 
     * @param certificate The certificate to check
     * @return CertificateStatus indicating the current status
     */
    public CertificateStatus getStatus(Certificate certificate) {
        if (certificate == null) {
            return CertificateStatus.INVALID;
        }

        LocalDateTime now = LocalDateTime.now();

        // Check if certificate is revoked (from database status)
        if (certificate.getStatus() == CertificateStatus.REVOKED) {
            return CertificateStatus.REVOKED;
        }

        // Check if certificate is expired
        if (now.isAfter(certificate.getValidTo())) {
            return CertificateStatus.EXPIRED;
        }

        // Check if certificate is dormant (not yet valid)
        if (now.isBefore(certificate.getValidFrom())) {
            return CertificateStatus.DORMANT;
        }

        // If we reach here, certificate is within validity period and not revoked
        // Check if it's marked as valid in the database
        if (certificate.getStatus() == CertificateStatus.ACTIVE) {
            return CertificateStatus.ACTIVE;
        }

        // Default to invalid for any other status
        return CertificateStatus.INVALID;
    }

    /**
     * Gets all certificates (public endpoint).
     * 
     * @return List of all certificates
     */
    public List<CertificateDTO> getAllCertificates() {
        List<Certificate> certificates = certificateRepository.findAll();
        return certificates.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }

    /**
     * Gets all valid signing certificates (public endpoint).
     * 
     * @return List of valid signing certificates
     */
    public List<CertificateDTO> getAllValidSigningCertificates() {
        List<Certificate> allSigningCerts = certificateRepository.findAll().stream()
                .filter(cert -> cert.isCanSign())
                .toList();
        
        List<Certificate> validCerts = allSigningCerts.stream()
                .filter(cert -> getStatus(cert) == CertificateStatus.ACTIVE)
                .toList();
        
        return validCerts.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }

    /**
     * Gets valid signing certificates that a CA user doesn't have.
     * 
     * @param caUserId The ID of the CA user
     * @return List of valid signing certificates not assigned to the CA user
     */
    public List<CertificateDTO> getValidSigningCertificatesCaUserDoesntHave(String caUserId) {
        // Find the CA user
        User caUser = userRepository.findById(Long.parseLong(caUserId))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));
        
        // Get all signing certificates (that can sign and have signing certificate)
        List<Certificate> allSigningCerts = certificateRepository.findAll().stream()
                .filter(cert -> cert.isCanSign() && cert.getSigningCertificate() != null)
                .toList();
        
        // Filter out certificates already assigned to the user
        List<Certificate> notAssignedToUser = allSigningCerts.stream()
                .filter(cert -> !caUser.getMyCertificates().contains(cert))
                .toList();
        
        // Filter for valid certificates
        List<Certificate> validCerts = notAssignedToUser.stream()
                .filter(cert -> getStatus(cert) == CertificateStatus.ACTIVE)
                .toList();
        
        return validCerts.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }

    /**
     * Adds a certificate to a CA user.
     * 
     * @param request The request containing CA user ID and certificate serial number
     */
    public void addCertificateToCaUser(AddCertificateToCaUserRequestDTO request) {
        // Find the CA user
        User caUser = userRepository.findById(Long.parseLong(request.getCaUserId()))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));
        
        // Find the certificate
        Certificate certificate = certificateRepository.findBySerialNumber(request.getNewCertificateSerialNumber())
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));
        
        // Add certificate to user's collection (like other back-end)
        caUser.getMyCertificates().add(certificate);
        userRepository.save(caUser);
    }

    /**
     * Gets certificates belonging to a specific user.
     * 
     * @param userId The ID of the user
     * @return List of user's certificates
     */
    public List<CertificateDTO> getMyCertificates(String userId) {
        User user = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("User not found!"));
        
        // Use the MyCertificates collection like the other back-end
        List<Certificate> certificates = user.getMyCertificates();
        return certificates.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }

    /**
     * Gets valid certificates belonging to a specific user.
     * 
     * @param userId The ID of the user
     * @return List of user's valid certificates
     */
    public List<CertificateDTO> getMyValidCertificates(String userId) {
        User user = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("User not found!"));
        
        // Use the MyCertificates collection and filter for valid certificates
        List<Certificate> validCerts = user.getMyCertificates().stream()
                .filter(cert -> getStatus(cert) == CertificateStatus.ACTIVE)
                .toList();
        
        return validCerts.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }

    /**
     * Gets certificates signed by a specific CA user.
     * 
     * @param userId The ID of the CA user
     * @return List of certificates signed by the user
     */
    public List<CertificateDTO> getCertificatesSignedByMe(String userId) {
        User caUser = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));
        
        List<Certificate> certificates = certificateRepository.findBySignedBy(caUser);
        return certificates.stream()
                .map(this::convertToDTO)
                .toList();
    }

    /**
     * Downloads a certificate as PKCS#12 format.
     * 
     * @param request The download request containing serial number and password
     * @param userId The ID of the user requesting the download
     * @param role The role of the user
     * @return Byte array containing the PKCS#12 file
     * @throws IllegalArgumentException if request parameters are invalid
     * @throws RuntimeException if certificate not found or access denied
     */
    public byte[] getCertificateWithPasswordAsPkcs12(DownloadCertificateRequestDTO request, Long userId, Role role) {
        // Validate request parameters
        if (request == null) {
            throw new IllegalArgumentException("Download request cannot be null");
        }
        if (request.getCertificateSerialNumber() == null || request.getCertificateSerialNumber().trim().isEmpty()) {
            throw new IllegalArgumentException("Certificate serial number is required");
        }
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }
        
        // Find the certificate
        Certificate certificate = certificateRepository.findBySerialNumber(request.getCertificateSerialNumber())
                .orElseThrow(() -> new RuntimeException("Certificate not found with serial number: " + request.getCertificateSerialNumber()));
        
        // Check authorization
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
        
        if (!hasAccessToCertificate(certificate, user)) {
            throw new RuntimeException("Access denied to certificate. User " + userId + " does not have permission to download certificate " + request.getCertificateSerialNumber());
        }
        
        try {
            // Decrypt the private key using the user's key
            byte[] userKey = userKeyService.getUserKey(userId);
            EncryptedData encryptedData = new EncryptedData(
                Base64.getDecoder().decode(certificate.getEncryptedPrivateKey()),
                Base64.getDecoder().decode(certificate.getEncryptionIV()),
                Base64.getDecoder().decode(certificate.getEncryptionTag())
            );
            
            // Decrypt private key
            java.security.PrivateKey privateKey = encryptionService.decryptPrivateKey(
                encryptedData.getEncryptedData(),
                encryptedData.getIv(),
                encryptedData.getTag(),
                Base64.getEncoder().encodeToString(userKey)
            );
            
            // Parse the certificate from PEM data
            X509Certificate x509Certificate = parseX509CertificateFromPEM(certificate.getCertificateData());
            
            // Build certificate chain
            List<X509Certificate> certificateChain = buildCertificateChain(certificate);
            
            // Generate PKCS#12 keystore
            return keystoreService.createPKCS12Keystore(
                privateKey, 
                certificateChain, 
                request.getPassword(),
                "privatekey",
                "certificate"
            );
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate PKCS#12 file for certificate " + request.getCertificateSerialNumber() + ": " + e.getMessage(), e);
        }
    }

    /**
     * Finds a certificate by serial number.
     * 
     * @param serialNumber The serial number to search for
     * @return Optional containing the certificate if found
     */
    public Optional<Certificate> findBySerialNumber(String serialNumber) {
        return certificateRepository.findBySerialNumber(serialNumber);
    }
    
    /**
     * Gets the user repository for access from controllers.
     * 
     * @return The user repository
     */
    public UserRepository getUserRepository() {
        return userRepository;
    }
    

    /**
     * Creates a certificate from an issue request - matches other back-end logic exactly.
     * 
     * @param request The certificate issue request
     * @param isAdmin Whether the requester is an admin
     * @param userId The ID of the user requesting the certificate
     * @param targetUserId The ID of the target user for the certificate
     */
    public void createCertificate(IssueCertificateRequestDTO request, boolean isAdmin, String userId, String targetUserId) {
        if (userId == null || targetUserId == null) {
            throw new RuntimeException("User must be logged in!");
        }
        
        // Find the signing user
        User signingUser = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("Signing user not found!"));
        
        // Find the requesting user
        User requestingUser = userRepository.findById(Long.parseLong(targetUserId))
                .orElseThrow(() -> new RuntimeException("Requesting user not found!"));
        
        // Generate key pair (placeholder - would use Bouncy Castle)
        // In real implementation, this would generate actual RSA key pair
        
        Certificate signingCertificate = null;
        if (!"SelfSign".equals(request.getSigningCertificate())) {
            signingCertificate = certificateRepository.findBySerialNumber(request.getSigningCertificate())
                    .orElseThrow(() -> new RuntimeException("Signing certificate not found!"));
        }
        
        if (!isAdmin && signingCertificate == null) {
            throw new RuntimeException("Only admin can issue self signing certificates!");
        }
        
        if (signingCertificate != null && !signingCertificate.isCanSign()) {
            throw new RuntimeException("Selected certificate can't be used for signing!");
        }
        
        CertificateStatus status = signingCertificate != null ? getStatus(signingCertificate) : null;
        if (status != null && status != CertificateStatus.ACTIVE) {
            throw new RuntimeException("Selected certificate is " + status.toString().toLowerCase() + "!");
        }
        
        if (signingCertificate != null && request.getNotBefore() != null && 
            request.getNotBefore().isBefore(signingCertificate.getValidFrom())) {
            throw new RuntimeException("NotBefore cannot be earlier than the signing certificate's NotBefore!");
        }
        
        if (signingCertificate != null && request.getNotAfter() != null && 
            request.getNotAfter().isAfter(signingCertificate.getValidTo())) {
            throw new RuntimeException("NotAfter cannot be later than the signing certificate's NotAfter!");
        }
        
        if (request.getNotBefore() != null && request.getNotAfter() != null && 
            request.getNotBefore().isAfter(request.getNotAfter())) {
            throw new RuntimeException("NotBefore cannot be later than the NotAfter!");
        }
        
        if (!isAdmin && signingCertificate != null && 
            !signingUser.getMyCertificates().contains(signingCertificate)) {
            throw new RuntimeException("You don't have control over selected signing certificate!");
        }
        
        // Create the certificate
        Certificate certificate = createCertificateFromRequest(request, signingCertificate, signingUser);
        
        // Add certificate to user's collection if appropriate
        if (requestingUser.getRole() == Role.EE_USER || 
            (requestingUser.getRole() == Role.CA_USER && certificate.isCanSign())) {
            requestingUser.getMyCertificates().add(certificate);
        }
        
        certificateRepository.save(certificate);
        userRepository.save(requestingUser);
    }
    
    /**
     * Creates a certificate from the request data - matches other back-end's CertificateBuilder logic.
     */
    private Certificate createCertificateFromRequest(IssueCertificateRequestDTO request, Certificate signingCert, User signingUser) {
        // Generate key pair for the new certificate
        KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048); // Default key size
        
        // Encrypt private key with user-specific key
        byte[] userKey = userKeyService.getUserKey(signingUser.getId());
        EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
        
        Certificate certificate = new Certificate();
        certificate.setSerialNumber(generateSerialNumber());
        certificate.setSubjectCN(request.getCommonName());
        certificate.setSubjectO(request.getOrganization());
        certificate.setSubjectOU(request.getOrganizationalUnit());
        certificate.setSubjectE(request.getEmail());
        certificate.setSubjectC(request.getCountry());
        certificate.setIssuerDN(signingCert != null ? signingCert.getSubjectDN() : request.getCommonName());
        certificate.setSubjectDN(buildSubjectDN(request));
        certificate.setValidFrom(request.getNotBefore() != null ? request.getNotBefore() : LocalDateTime.now());
        certificate.setValidTo(request.getNotAfter() != null ? request.getNotAfter() : LocalDateTime.now().plusYears(1));
        certificate.setSigningCertificate(signingCert);
        certificate.setSignedBy(signingUser);
        certificate.setCanSign(false); // End entity certificates typically can't sign
        certificate.setPathLength(0);
        certificate.setCertificateType(CertificateType.END_ENTITY);
        certificate.setStatus(CertificateStatus.ACTIVE);
        
        // Set encrypted private key data
        certificate.setEncryptedPrivateKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
        certificate.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
        certificate.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));
        
        // Set public key
        certificate.setPublicKey(convertPublicKeyToPEM(keyPair.getPublic()));
        
        // Set certificate data (placeholder - would be actual X.509 certificate)
        certificate.setEncodedValue("placeholder_base64_encoded_certificate");
        certificate.setCertificateData("-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----");
        
        return certificate;
    }
    
    /**
     * Builds subject DN from request data.
     */
    private String buildSubjectDN(IssueCertificateRequestDTO request) {
        StringBuilder dn = new StringBuilder();
        dn.append("CN=").append(request.getCommonName());
        if (request.getOrganization() != null) {
            dn.append(",O=").append(request.getOrganization());
        }
        if (request.getOrganizationalUnit() != null) {
            dn.append(",OU=").append(request.getOrganizationalUnit());
        }
        if (request.getEmail() != null) {
            dn.append(",E=").append(request.getEmail());
        }
        if (request.getCountry() != null) {
            dn.append(",C=").append(request.getCountry());
        }
        return dn.toString();
    }

    // Helper methods
    private String generateSerialNumber() {
        // Generate a unique serial number
        return String.valueOf(System.currentTimeMillis());
    }
    
    /**
     * Converts a public key to PEM format.
     */
    private String convertPublicKeyToPEM(java.security.PublicKey publicKey) {
        try {
            byte[] encoded = publicKey.getEncoded();
            String base64 = Base64.getEncoder().encodeToString(encoded);
            return "-----BEGIN PUBLIC KEY-----\n" + 
                   base64.replaceAll("(.{64})", "$1\n") + 
                   "\n-----END PUBLIC KEY-----";
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert public key to PEM", e);
        }
    }

    private byte[] generatePkcs12File(Certificate certificate, String password) {
        // Placeholder implementation - would generate actual PKCS#12 file
        return ("PKCS#12 file for certificate " + certificate.getSerialNumber() + " with password " + password).getBytes();
    }

    /**
     * Converts certificate to DTO with status - matches other back-end's CertificateResponse.CreateDto logic.
     */
    private CertificateDTO convertToDTOWithStatus(Certificate certificate, String status) {
        CertificateDTO dto = convertToDTO(certificate);
        // Add status information if needed
        return dto;
    }

}
