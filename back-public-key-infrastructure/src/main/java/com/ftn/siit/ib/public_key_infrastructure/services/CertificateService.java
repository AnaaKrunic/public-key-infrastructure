package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateTemplate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateTemplateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;

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
    private final CertificateTemplateRepository templateRepository;
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
    private final com.ftn.siit.ib.public_key_infrastructure.config.ApplicationConfig applicationConfig;

    public CertificateService(
            CertificateRepository certificateRepository,
            CertificateTemplateRepository templateRepository,
            UserRepository userRepository,
            ValidationService validationService,
            CertificateGeneratorService certificateGeneratorService,
            CertificateSignerService certificateSignerService,
            EncryptionService encryptionService,
            KeyPairGeneratorService keyPairGeneratorService,
            KeystoreService keystoreService,
            CRLService crlService,
            MasterKeyService masterKeyService,
            UserKeyService userKeyService,
            com.ftn.siit.ib.public_key_infrastructure.config.ApplicationConfig applicationConfig) {
        this.certificateRepository = certificateRepository;
        this.templateRepository = templateRepository;
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
        this.applicationConfig = applicationConfig;
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
        System.out.println("INFO: createRootCertificate of CertificateService called");
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
        EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
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
        try {
            certificateEntity.setEncodedValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new RuntimeException("Failed to encode certificate", e);
        }
        certificateEntity.setKeyUsage(String.join(",", dto.getKeyUsage()));
        certificateEntity.setPathLength(dto.getBasicConstraints().getPathLength());
        certificateEntity.setCrlDistributionPoint(applicationConfig.getCrlDistributionPointUrl());
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
     * @param user The admin user creating the certificate (must have ADMIN role)
     * @return CertificateDTO containing the created certificate details
     * @throws IllegalArgumentException if dto or admin is null
     * @throws ValidationException if validation fails
     * @throws UnauthorizedException if admin does not have ADMIN role
     * @throws NotFoundException if issuer certificate not found
     */
    public CertificateDTO createIntermediateCertificate(CreateIntermediateCertificateDTO dto, User user) {
        System.out.println("INFO: createIntermediateCertificate of CertificateService called");
        // Validate parameters
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (user == null) {
            throw new IllegalArgumentException("Admin cannot be null");
        }
        if (user.getRole() == Role.ADMIN) {

        } else if (user.getRole() == Role.CA_USER){
            // CA users can create intermediate certificates only using their own CA certificates
            boolean hasAccess = false;
            Certificate issuerCert = certificateRepository.findById(dto.getIssuerCertificateId())
                .orElseThrow(() -> new NotFoundException("Issuer certificate not found"));
            if(dto.getSubjectO().equals(user.getOrganization()) &&
               issuerCert.getSubjectO().equals(user.getOrganization())){
                hasAccess = true;
            }
            if (!hasAccess) {
                throw new UnauthorizedException("CA_USER can only create intermediate certificates using certificates from their organization");
            }
        } else{
            throw new UnauthorizedException("Only ADMIN and CA users can create intermediate certificates");
        }

        // Fetch issuer certificate
        Certificate issuer = certificateRepository.findById(dto.getIssuerCertificateId())
            .orElseThrow(() -> new NotFoundException("Issuer certificate not found"));

        // Validate issuer certificate
        validationService.validateIssuerCertificate(issuer);

        // Validate that issuer's validity period covers the new certificate's validity period
        LocalDateTime newCertValidFrom = LocalDateTime.now();
        LocalDateTime newCertValidTo = LocalDateTime.now().plusDays(dto.getValidityDays());
        validationService.validateCertificateValidityPeriod(issuer, newCertValidFrom, newCertValidTo);

        // Path length constraints eliminated - all CA certificates can issue unlimited certificates
        System.out.println("DEBUG: Path length constraints eliminated - unlimited certificate issuance allowed");

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

        // Decrypt issuer's private key using the issuer's user key
        byte[] issuerUserKey = userKeyService.getUserKey(issuer.getSignedBy().getId());
        java.security.PrivateKey issuerPrivateKey = encryptionService.decryptPrivateKey(
            Base64.getDecoder().decode(issuer.getEncryptedPrivateKey()),
            Base64.getDecoder().decode(issuer.getEncryptionIV()),
            Base64.getDecoder().decode(issuer.getEncryptionTag()),
            Base64.getEncoder().encodeToString(issuerUserKey)
        );

        // Parse issuer's public key
        java.security.PublicKey issuerPublicKey = parsePublicKeyFromPEM(issuer.getPublicKey());

        // Generate intermediate certificate
        X509Certificate certificate = certificateGeneratorService.generateIntermediateCertificate(
            keyPair, subjectDN, issuerDN, issuerPrivateKey, issuerPublicKey,
            dto.getValidityDays(), dto.getKeyUsage(), dto.getBasicConstraints().getPathLength()
        );

        // Encrypt private key with user-specific key
        byte[] userKey = userKeyService.getUserKey(user.getId());
        EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
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
        // Set issuer fields from the signing certificate's SUBJECT (not its issuer)
        certificateEntity.setIssuerCN(issuer.getSubjectCN());
        certificateEntity.setIssuerO(issuer.getSubjectO());
        certificateEntity.setIssuerOU(issuer.getSubjectOU());
        certificateEntity.setIssuerL(issuer.getSubjectL());
        certificateEntity.setIssuerST(issuer.getSubjectST());
        certificateEntity.setIssuerC(issuer.getSubjectC());
        certificateEntity.setIssuerE(issuer.getSubjectE());
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
        try {
            certificateEntity.setEncodedValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new RuntimeException("Failed to encode certificate", e);
        }
        certificateEntity.setKeyUsage(String.join(",", dto.getKeyUsage()));
        certificateEntity.setPathLength(dto.getBasicConstraints().getPathLength());
        certificateEntity.setCrlDistributionPoint(applicationConfig.getCrlDistributionPointUrl());
        // Owner removed - using many-to-many relationship now
        certificateEntity.setIssuerCertificate(issuer);
        certificateEntity.setSignedBy(user);
        certificateEntity.setSigningCertificate(issuer);
        certificateEntity.setSigningOrganization(
                user.getOrganization() // Organization from admin since issuer owner removed
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
    public CertificateDTO createEndEntityCertificate(CreateEndEntityCertificateDTO dto, User requester, Boolean isFromCSR) {
        System.out.println("INFO: createEndEntityCertificate of CertificateService called");
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
        else if (requester.getRole() == Role.CA_USER) {
            // CA users can create intermediate certificates only using their own CA certificates
            boolean giveAccess = true;
            Certificate issuerCert = certificateRepository.findById(dto.getIssuerCertificateId())
                    .orElseThrow(() -> new NotFoundException("Issuer certificate not found"));

            if (!isFromCSR &&
                    dto.getSubjectO().equals(requester.getOrganization()) &&
                    issuerCert.getSubjectO().equals(requester.getOrganization())) {
                giveAccess = false;
            }
            if (!giveAccess) {
                throw new UnauthorizedException("CA_USER can only create intermediate certificates using certificates from their organization");
            }
        }

        // If templateId provided, validate against template constraints and extensions policy
        CertificateTemplate template = null;
        if (dto.getTemplateId() != null) {
            template = templateRepository.findById(dto.getTemplateId())
                .orElseThrow(() -> new NotFoundException("Template not found"));
            validationService.validateTemplateConstraints(template, dto);
        }
        
        // Validate template and extensions policy
        validationService.validateTemplateAndExtensionsPolicy(
            template, 
            dto.getKeyUsage(), 
            dto.getExtendedKeyUsage(), 
            issuer, 
            CertificateType.END_ENTITY
        );

        // Validate issuer certificate
        validationService.validateIssuerCertificate(issuer);

        // Validate that issuer's validity period covers the new certificate's validity period
        LocalDateTime newCertValidFrom = LocalDateTime.now();
        LocalDateTime newCertValidTo = LocalDateTime.now().plusDays(dto.getValidityDays());
        validationService.validateCertificateValidityPeriod(issuer, newCertValidFrom, newCertValidTo);

        // Generate key pair
        KeyPair keyPair = keyPairGeneratorService.generateKeyPair(dto.getKeySize());

        // Build subject and issuer DNs
        System.out.println("DEBUG: Building subject DN with CN=" + dto.getSubjectCN());
        X500Name subjectDN = certificateGeneratorService.buildX500Name(
            dto.getSubjectCN(), dto.getSubjectO(), dto.getSubjectOU(),
            dto.getSubjectL(), dto.getSubjectST(), dto.getSubjectC(), dto.getSubjectE()
        );
        // For end-entity certificates, the issuer DN should be the SUBJECT of the signing certificate
        System.out.println("DEBUG: Building issuer DN with CN=" + issuer.getSubjectCN() + 
            ", O=" + issuer.getSubjectO() + ", OU=" + issuer.getSubjectOU() + 
            ", L=" + issuer.getSubjectL() + ", ST=" + issuer.getSubjectST() + 
            ", C=" + issuer.getSubjectC() + ", E=" + issuer.getSubjectE());
        X500Name issuerDN = certificateGeneratorService.buildX500Name(
            issuer.getSubjectCN(), issuer.getSubjectO(), issuer.getSubjectOU(),
            issuer.getSubjectL(), issuer.getSubjectST(), issuer.getSubjectC(), issuer.getSubjectE()
        );

        // Decrypt issuer's private key using the issuer's user key
        byte[] issuerUserKey = userKeyService.getUserKey(issuer.getSignedBy().getId());
        java.security.PrivateKey issuerPrivateKey = encryptionService.decryptPrivateKey(
            Base64.getDecoder().decode(issuer.getEncryptedPrivateKey()),
            Base64.getDecoder().decode(issuer.getEncryptionIV()),
            Base64.getDecoder().decode(issuer.getEncryptionTag()),
            Base64.getEncoder().encodeToString(issuerUserKey)
        );

        // Parse issuer's public key
        java.security.PublicKey issuerPublicKey = parsePublicKeyFromPEM(issuer.getPublicKey());

        // Combine template and user extensions
        List<String> finalKeyUsage = new ArrayList<>();
        List<String> finalExtendedKeyUsage = new ArrayList<>();
        
        // Add template extensions first
        if (template != null) {
            if (template.getKeyUsage() != null && !template.getKeyUsage().trim().isEmpty()) {
                String[] templateKeyUsage = template.getKeyUsage().split(",");
                for (String usage : templateKeyUsage) {
                    finalKeyUsage.add(usage.trim());
                }
            }
            
            if (template.getExtendedKeyUsage() != null && !template.getExtendedKeyUsage().trim().isEmpty()) {
                String[] templateExtendedKeyUsage = template.getExtendedKeyUsage().split(",");
                for (String usage : templateExtendedKeyUsage) {
                    finalExtendedKeyUsage.add(usage.trim());
                }
            }
        }
        
        // Add user-requested extensions (avoiding duplicates)
        if (dto.getKeyUsage() != null) {
            for (String usage : dto.getKeyUsage()) {
                if (!finalKeyUsage.contains(usage)) {
                    finalKeyUsage.add(usage);
                }
            }
        }
        
        if (dto.getExtendedKeyUsage() != null) {
            for (String usage : dto.getExtendedKeyUsage()) {
                if (!finalExtendedKeyUsage.contains(usage)) {
                    finalExtendedKeyUsage.add(usage);
                }
            }
        }

        // Generate end-entity certificate
        System.out.println("DEBUG: About to generate end-entity certificate with validityDays=" + dto.getValidityDays());
        X509Certificate certificate;
        try {
            certificate = certificateGeneratorService.generateEndEntityCertificate(
                keyPair, subjectDN, issuerDN, issuerPrivateKey, issuerPublicKey,
                dto.getValidityDays(), finalKeyUsage, finalExtendedKeyUsage, 
                dto.getSubjectAlternativeNames(), dto.getCrlDistributionPoint()
            );
        } catch (Exception e) {
            System.err.println("ERROR: Failed to generate end-entity certificate: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error creating certificate: " + e.getMessage(), e);
        }

        // Encrypt private key with user-specific key
        byte[] userKey = userKeyService.getUserKey(requester.getId());
        EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
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
        // Set issuer fields from the signing certificate's SUBJECT (not its issuer)
        certificateEntity.setIssuerCN(issuer.getSubjectCN());
        certificateEntity.setIssuerO(issuer.getSubjectO());
        certificateEntity.setIssuerOU(issuer.getSubjectOU());
        certificateEntity.setIssuerL(issuer.getSubjectL());
        certificateEntity.setIssuerST(issuer.getSubjectST());
        certificateEntity.setIssuerC(issuer.getSubjectC());
        certificateEntity.setIssuerE(issuer.getSubjectE());
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
        try {
            certificateEntity.setEncodedValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new RuntimeException("Failed to encode certificate", e);
        }
        certificateEntity.setKeyUsage(String.join(",", finalKeyUsage));
        certificateEntity.setExtendedKeyUsage(finalExtendedKeyUsage.isEmpty() ? null : String.join(",", finalExtendedKeyUsage));
        certificateEntity.setSubjectAlternativeNames(dto.getSubjectAlternativeNames() != null ? String.join(",", dto.getSubjectAlternativeNames()) : null);
        certificateEntity.setCrlDistributionPoint(applicationConfig.getCrlDistributionPointUrl());
        // Owner removed - using many-to-many relationship now
        certificateEntity.setIssuerCertificate(issuer);
        certificateEntity.setSignedBy(requester);
        certificateEntity.setSigningCertificate(issuer);
        certificateEntity.setSigningOrganization(
                requester.getOrganization() // Set to requester's organization
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
        System.out.println("INFO: getCertificateBySerialNumber of CertificateService called");
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
        
        // CA_USER can access certificates from their organization (including those that signed their CA)
        if (requester.getRole() == Role.CA_USER) {
            // Check if certificate belongs to the CA user's organization
            boolean hasAccess = certificate.getSigningOrganization() != null && 
                              certificate.getSigningOrganization().equals(requester.getOrganization());
            
            // Also check if certificate was signed by a CA user from the same organization
            if (!hasAccess && certificate.getSignedBy() != null && 
                certificate.getSignedBy().getRole() == Role.CA_USER && 
                certificate.getSignedBy().getOrganization().equals(requester.getOrganization())) {
                hasAccess = true;
            }
            
            return hasAccess;
        }
        
        // EE_USER can access their own certificates (certificates in their myCertificates collection)
        if (requester.getRole() == Role.EE_USER) {
            // Compare by ID to avoid issues with JPA entity instance comparison
            return requester.getMyCertificates().stream()
                    .anyMatch(cert -> cert.getId().equals(certificate.getId()));
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
            // CA_USER can see certificates from their organization (including those that signed their CA)
            List<CertificateDTO> orgCerts = getValidSigningCertificatesForOrganization(requester.getOrganization());
            // Convert DTOs to entities for consistency with the method signature
            List<Certificate> orgCertEntities = orgCerts.stream()
                .map(dto -> {
                    Certificate cert = new Certificate();
                    cert.setId(dto.getId());
                    cert.setSerialNumber(dto.getSerialNumber());
                    cert.setSubjectCN(dto.getSubjectCN());
                    cert.setIssuerCN(dto.getIssuerCN());
                    cert.setValidFrom(dto.getValidFrom());
                    cert.setValidTo(dto.getValidTo());
                    cert.setCanSign(dto.getCanSign());
                    cert.setPathLength(dto.getPathLength());
                    cert.setStatus(dto.getStatus());
                    return cert;
                })
                .toList();
            certificates = new org.springframework.data.domain.PageImpl<>(orgCertEntities, pageable, orgCertEntities.size());
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

        // Check authorization
        if (!hasAccessToCertificate(certificate, requester)) {
            throw new ForbiddenException("Access denied to certificate");
        }

        // Only EE users can download private keys
        if (requester.getRole() != Role.EE_USER) {
            throw new ForbiddenException("Access denied. Only end-entity users can download certificates with private keys. Admins and CA users can only download certificate data (PEM format).");
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

        // Determine which user's key to use for decryption
        // The private key was encrypted with the certificate owner's key (signedBy user)
        User keyOwner = certificate.getSignedBy();
        if (keyOwner == null) {
            throw new RuntimeException("Certificate has no owner (signedBy is null). Cannot decrypt private key.");
        }
        
        // Use the certificate owner's key to decrypt the private key
        byte[] ownerKey = userKeyService.getUserKey(keyOwner.getId());
        
        // Decrypt private key using the owner's key
        java.security.PrivateKey privateKey = encryptionService.decryptPrivateKey(
            Base64.getDecoder().decode(certificate.getEncryptedPrivateKey()),
            Base64.getDecoder().decode(certificate.getEncryptionIV()),
            Base64.getDecoder().decode(certificate.getEncryptionTag()),
            Base64.getEncoder().encodeToString(ownerKey)
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
     * Helper method to parse public key from PEM string.
     * 
     * Supports standard PEM format for public keys:
     * - -----BEGIN PUBLIC KEY----- (X.509 SubjectPublicKeyInfo format)
     * - -----BEGIN RSA PUBLIC KEY----- (PKCS#1 RSA format)
     * 
     * @param pemString The PEM-encoded public key string
     * @return PublicKey object
     * @throws IllegalArgumentException if pemString is null or empty
     * @throws RuntimeException if parsing fails
     */
    private java.security.PublicKey parsePublicKeyFromPEM(String pemString) {
        if (pemString == null || pemString.trim().isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty");
        }

        try {
            // Remove PEM headers and footers
            String cleanPem = pemString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64 to get DER data
            byte[] derData = java.util.Base64.getDecoder().decode(cleanPem);
            
            // Create key factory
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            
            // Parse X.509 format (SubjectPublicKeyInfo)
            // This is the standard format for "BEGIN PUBLIC KEY"
            java.security.spec.X509EncodedKeySpec keySpec = 
                new java.security.spec.X509EncodedKeySpec(derData);
            
            return keyFactory.generatePublic(keySpec);
        } catch (java.security.spec.InvalidKeySpecException e) {
            throw new RuntimeException("Invalid public key format: " + e.getMessage(), e);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not available: " + e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid Base64 encoding in PEM data: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse public key from PEM: " + e.getMessage(), e);
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

        dto.setSigningOrganization(certificate.getSigningOrganization());
        
        return dto;
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
     * Gets all valid CA certificates (excluding root certificates).
     * Root certificates are identified by having no issuer certificate (self-signed).
     * This is used by EE users when requesting certificates.
     * Returns only basic information (CN, O, OU, serial number).
     * 
     * @return List of valid CA certificates with basic info only (non-root)
     */
    public List<BasicCACertificateDTO> getAllValidCACertificates() {
        List<Certificate> allCaCerts = certificateRepository.findAll().stream()
                .filter(cert -> cert.isCanSign())
                .filter(cert -> cert.getIssuerCertificate() != null) // Exclude root certificates
                .filter(cert -> getStatus(cert) == CertificateStatus.ACTIVE)
                .toList();
        
        return allCaCerts.stream()
                .map(this::convertToBasicCADTO)
                .toList();
    }
    
    /**
     * Converts a Certificate to BasicCACertificateDTO with only essential info.
     * 
     * @param certificate The certificate to convert
     * @return BasicCACertificateDTO with basic information
     */
    private BasicCACertificateDTO convertToBasicCADTO(Certificate certificate) {
        return new BasicCACertificateDTO(
                certificate.getSerialNumber(),
                certificate.getSubjectCN(),
                certificate.getSubjectO(),
                certificate.getSubjectOU()
        );
    }

    /**
     * Gets all CA certificates from a specific CA user's chain.
     * This includes all CA certificates that the user can sign with (owned + up the chain).
     * 
     * @param caUserId The ID of the CA user
     * @return List of CA certificates in the user's chain
     */
    public List<CertificateDTO> getCACertificatesFromUserChain(String caUserId) {
        User caUser = userRepository.findById(Long.parseLong(caUserId))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));
        
        // Get all CA certificates owned by this user
        List<Certificate> ownedCaCerts = caUser.getMyCertificates().stream()
                .filter(cert -> cert.isCanSign())
                .toList();
        
        // Collect all CA certificates in the chain (including issuers up the chain)
        Set<Certificate> allCaInChain = new HashSet<>(ownedCaCerts);
        
        for (Certificate ownedCert : ownedCaCerts) {
            // Add all CA certificates up the chain (issuers)
            collectIssuersUpTheChain(ownedCert, allCaInChain);
        }
        
        return allCaInChain.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }

    /**
     * Gets valid signing certificates for a specific organization.
     * CA users can use ALL certificates created by their organization, including those that signed their CA.
     * 
     * @param organization The organization name
     * @return List of valid signing certificates for the organization
     */
    public List<CertificateDTO> getValidSigningCertificatesForOrganization(String organization) {
        // Get all signing certificates
        List<Certificate> allSigningCerts = certificateRepository.findAll().stream()
                .filter(cert -> cert.isCanSign())
                .toList();
        
        // Filter for certificates that belong to the organization
        // CA users can use ALL certificates created by their organization (including those that signed their CA)
        List<Certificate> orgSigningCerts = allSigningCerts.stream()
                .filter(cert -> {
                    // Check if signingOrganization matches (certificates created by this organization)
                    if (organization.equals(cert.getSigningOrganization())) {
                        return true;
                    }
                    
                    // Check if certificate was signed by a CA user from this organization
                    if (cert.getSignedBy() != null && 
                        cert.getSignedBy().getRole() == Role.CA_USER && 
                        organization.equals(cert.getSignedBy().getOrganization())) {
                        return true;
                    }
                    
                    return false;
                })
                .toList();
        
        List<Certificate> validCerts = orgSigningCerts.stream()
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
     * Only certificates from the same organization as the CA user can be assigned.
     * 
     * @param request The request containing CA user ID and certificate serial number
     * @throws RuntimeException if CA user not found, user is not a CA role, certificate not found, or organizations don't match
     */
    public void addCertificateToCaUser(AddCertificateToCaUserRequestDTO request) {
        // Find the CA user
        User caUser = userRepository.findById(Long.parseLong(request.getCaUserId()))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));

        // Ensure CA role
        if (caUser.getRole() != Role.CA_USER) {
            throw new RuntimeException("User is not a CA user!");
        }
        
        // Find the certificate
        Certificate certificate = certificateRepository.findBySerialNumber(request.getNewCertificateSerialNumber())
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        // Ensure CA user and certificate are from same organization
        if (caUser.getOrganization() == null || certificate.getSigningOrganization() == null) {
            throw new RuntimeException("CA user or certificate organization is not set!");
        }
        
        if (!caUser.getOrganization().equals(certificate.getSubjectO())) {
            throw new RuntimeException("CA user and certificate must belong to the same organization! " +
                    "User organization: " + caUser.getOrganization() + 
                    ", Certificate organization: " + certificate.getSigningOrganization());
        }
        
        // Check if certificate is already assigned to this user
        if (caUser.getMyCertificates().contains(certificate)) {
            throw new RuntimeException("Certificate is already assigned to this CA user!");
        }
        
        // Add certificate to user's collection
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

        System.out.println("DEBUG: Getting certificates for user " + userId);
        System.out.println("DEBUG: User " + user.getEmail() + " has " + user.getMyCertificates().size() + " certificates");
        
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
     * Gets valid CA certificates (canSign = true) from the user's chain that can be used for signing.
     * This includes:
     * - CA certificates owned by the user
     * - CA certificates that signed the user's certificates (up the chain)
     * 
     * @param userId The ID of the CA user
     * @return List of valid CA certificates that can be used for signing
     */
    public List<CertificateDTO> getMyValidSigningCertificates(String userId) {
        User caUser = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));
        
        // Get all CA certificates owned by this user
        List<Certificate> ownedCaCerts = caUser.getMyCertificates().stream()
                .filter(cert -> cert.isCanSign())
                .filter(cert -> getStatus(cert) == CertificateStatus.ACTIVE)
                .toList();
        
        // Collect all CA certificates in the chain (including issuers up the chain)
        Set<Certificate> allSigningCertsInChain = new HashSet<>(ownedCaCerts);
        
        for (Certificate ownedCert : ownedCaCerts) {
            // Add all CA certificates up the chain (issuers)
            collectIssuersUpTheChain(ownedCert, allSigningCertsInChain);
        }
        
        return allSigningCertsInChain.stream()
                .filter(cert -> getStatus(cert) == CertificateStatus.ACTIVE)
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }
    
    /**
     * Recursively collects all CA certificates up the issuer chain.
     * 
     * @param certificate The certificate to start from
     * @param result The set to collect certificates into
     */
    private void collectIssuersUpTheChain(Certificate certificate, Set<Certificate> result) {
        Certificate issuer = certificate.getIssuerCertificate();
        
        if (issuer != null && issuer.isCanSign()) {
            // Avoid infinite loops
            if (!result.contains(issuer)) {
                result.add(issuer);
                // Recursively collect issuers up the chain
                collectIssuersUpTheChain(issuer, result);
            }
        }
    }

    /**
     * Gets all certificates in the CA user's chain.
     * This includes:
     * - Certificates they own (their CA certificates)
     * - Certificates signed by their CA certificates
     * - Certificates signed by those certificates (recursively down the chain)
     * 
     * @param userId The ID of the CA user
     * @return List of all certificates in the user's chain
     */
    public List<CertificateDTO> getCertificatesSignedByMe(String userId) {
        User caUser = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("CA user not found!"));
        
        // Get all CA certificates owned by this user
        List<Certificate> caCertificates = caUser.getMyCertificates().stream()
                .filter(cert -> cert.isCanSign())
                .toList();
        
        // Collect all certificates in the chain
        Set<Certificate> allCertificatesInChain = new HashSet<>();
        
        for (Certificate caCert : caCertificates) {
            // Add the CA certificate itself
            allCertificatesInChain.add(caCert);
            // Add all certificates issued by this CA certificate (recursively)
            collectCertificatesIssuedBy(caCert, allCertificatesInChain);
        }
        
        return allCertificatesInChain.stream()
                .map(cert -> convertToDTOWithStatus(cert, getStatus(cert).toString()))
                .toList();
    }
    
    /**
     * Recursively collects all certificates issued by a given certificate.
     * 
     * @param issuerCert The issuer certificate
     * @param result The set to collect certificates into
     */
    private void collectCertificatesIssuedBy(Certificate issuerCert, Set<Certificate> result) {
        // Find all certificates issued by this certificate
        List<Certificate> issuedCertificates = certificateRepository.findAll().stream()
                .filter(cert -> cert.getIssuerCertificate() != null && 
                               cert.getIssuerCertificate().getId().equals(issuerCert.getId()))
                .toList();
        
        for (Certificate issuedCert : issuedCertificates) {
            // Avoid infinite loops in case of circular references
            if (!result.contains(issuedCert)) {
                result.add(issuedCert);
                // Recursively collect certificates issued by this certificate
                collectCertificatesIssuedBy(issuedCert, result);
            }
        }
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
        
        // Only EE users can download private keys (PKCS12 with private key)
        if (user.getRole() != Role.EE_USER) {
            throw new RuntimeException("Access denied. Only end-entity users can download certificates with private keys. Admins and CA users can only download certificate data (PEM format).");
        }
        
        // Check if the certificate belongs to the user
        if (!hasAccessToCertificate(certificate, user)) {
            throw new RuntimeException("Access denied to certificate. User " + userId + " does not have permission to download certificate " + request.getCertificateSerialNumber());
        }
        
        try {
            System.out.println("DEBUG: Starting PKCS12 generation for certificate " + request.getCertificateSerialNumber() + " for user " + userId);
            
            // Determine which user's key to use for decryption
            // The private key was encrypted with the CA user's key (signedBy user who created/approved it)
            User caUser = certificate.getSignedBy();
            if (caUser == null) {
                throw new RuntimeException("Certificate has no signer (signedBy is null). Cannot decrypt private key.");
            }
            
            System.out.println("DEBUG: Certificate was created by user " + caUser.getId() + " (" + caUser.getEmail() + ")");
            System.out.println("DEBUG: Getting user key for CA user (user " + caUser.getId() + ")");
            
            // Use the CA user's key to decrypt the private key
            byte[] caUserKey = userKeyService.getUserKey(caUser.getId());
            System.out.println("DEBUG: Retrieved CA user key, length: " + caUserKey.length);
            
            EncryptionService.EncryptedData encryptedData = new EncryptionService.EncryptedData(
                Base64.getDecoder().decode(certificate.getEncryptedPrivateKey()),
                Base64.getDecoder().decode(certificate.getEncryptionIV()),
                Base64.getDecoder().decode(certificate.getEncryptionTag())
            );
            System.out.println("DEBUG: Created encrypted data object for private key decryption");
            
            // Decrypt private key using the CA user's key
            System.out.println("DEBUG: Calling encryption service to decrypt private key");
            java.security.PrivateKey privateKey = encryptionService.decryptPrivateKey(
                encryptedData.getEncryptedData(),
                encryptedData.getIv(),
                encryptedData.getTag(),
                Base64.getEncoder().encodeToString(caUserKey)
            );
            System.out.println("DEBUG: Successfully decrypted private key");
            
            // Parse the certificate from PEM data
            X509Certificate x509Certificate = parseX509CertificateFromPEM(certificate.getCertificateData());
            System.out.println("DEBUG: Successfully parsed X509Certificate");
            
            // Build certificate chain
            List<X509Certificate> certificateChain = buildCertificateChain(certificate);
            System.out.println("DEBUG: Built certificate chain with " + certificateChain.size() + " certificates");
            
            // Generate PKCS#12 keystore
            System.out.println("DEBUG: Creating PKCS12 keystore with password length: " + request.getPassword().length());
            byte[] pkcs12Bytes = keystoreService.createPKCS12Keystore(
                privateKey, 
                certificateChain, 
                request.getPassword(),
                "privatekey",
                "certificate"
            );
            System.out.println("DEBUG: Successfully created PKCS12 keystore, size: " + pkcs12Bytes.length + " bytes");
            return pkcs12Bytes;
            
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
        EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(keyPair.getPrivate(), Base64.getEncoder().encodeToString(userKey));
        
        Certificate certificate = new Certificate();
        certificate.setSerialNumber(generateSerialNumber());
        certificate.setSubjectCN(request.getCommonName());
        certificate.setSubjectO(request.getOrganization());
        certificate.setSubjectOU(request.getOrganizationalUnit());
        certificate.setSubjectE(request.getEmail());
        certificate.setSubjectC(request.getCountry());
        // Set issuer information from the signing certificate
        if (signingCert != null) {
            certificate.setIssuerCN(signingCert.getSubjectCN());
            certificate.setIssuerO(signingCert.getSubjectO());
            certificate.setIssuerOU(signingCert.getSubjectOU());
            certificate.setIssuerL(signingCert.getSubjectL());
            certificate.setIssuerST(signingCert.getSubjectST());
            certificate.setIssuerC(signingCert.getSubjectC());
            certificate.setIssuerE(signingCert.getSubjectE());
            certificate.setIssuerDN(signingCert.getSubjectDN());
        } else {
            // Self-signed certificate
            certificate.setIssuerCN(request.getCommonName());
            certificate.setIssuerO(request.getOrganization());
            certificate.setIssuerOU(request.getOrganizationalUnit());
            certificate.setIssuerC(request.getCountry());
            certificate.setIssuerE(request.getEmail());
            certificate.setIssuerDN(buildSubjectDN(request));
        }
        certificate.setSubjectDN(buildSubjectDN(request));
        certificate.setValidFrom(request.getNotBefore() != null ? request.getNotBefore() : LocalDateTime.now());
        certificate.setValidTo(request.getNotAfter() != null ? request.getNotAfter() : LocalDateTime.now().plusYears(1));
        certificate.setSigningCertificate(signingCert);
        certificate.setSignedBy(signingUser);
        certificate.setSigningOrganization(signingUser.getOrganization());
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
        
        // Generate actual X.509 certificate
        X509Certificate x509Certificate = generateX509Certificate(
            keyPair, 
            request, 
            signingCert, 
            signingUser,
            certificate.getValidFrom(),
            certificate.getValidTo()
        );
        
        // Export certificate to PEM format
        String certificatePEM = keystoreService.exportCertificateAsPEM(x509Certificate);
        certificate.setCertificateData(certificatePEM);
        
        // Set encoded value (Base64 of DER)
        try {
            certificate.setEncodedValue(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new RuntimeException("Failed to encode certificate", e);
        }
        
        return certificate;
    }
    
    /**
     * Generates an X.509 certificate based on the request parameters.
     * 
     * @param keyPair The key pair for the new certificate
     * @param request The certificate request with subject information
     * @param signingCert The signing certificate (null for self-signed root)
     * @param signingUser The user creating the certificate
     * @param validFrom Certificate validity start date
     * @param validTo Certificate validity end date
     * @return Generated X509Certificate
     */
    private X509Certificate generateX509Certificate(
            KeyPair keyPair,
            IssueCertificateRequestDTO request,
            Certificate signingCert,
            User signingUser,
            LocalDateTime validFrom,
            LocalDateTime validTo) {
        
        // Build subject DN
        X500Name subjectDN = certificateGeneratorService.buildX500Name(
            request.getCommonName(),
            request.getOrganization(),
            request.getOrganizationalUnit(),
            null, // locality
            null, // state
            request.getCountry(),
            request.getEmail()
        );
        
        // Calculate validity days
        int validityDays = (int) java.time.temporal.ChronoUnit.DAYS.between(validFrom, validTo);
        
        // Default key usage for end-entity certificates
        List<String> keyUsage = java.util.Arrays.asList("digitalSignature", "keyEncipherment");
        
        X509Certificate x509Certificate;
        
        if (signingCert == null) {
            // Self-signed root certificate
            x509Certificate = certificateGeneratorService.generateRootCertificate(
                keyPair,
                subjectDN,
                validityDays,
                keyUsage,
                null // pathLength
            );
        } else {
            // Signed by another certificate (end-entity or intermediate)
            // Build issuer DN from signing certificate
            X500Name issuerDN = certificateGeneratorService.buildX500Name(
                signingCert.getSubjectCN(),
                signingCert.getSubjectO(),
                signingCert.getSubjectOU(),
                signingCert.getSubjectL(),
                signingCert.getSubjectST(),
                signingCert.getSubjectC(),
                signingCert.getSubjectE()
            );
            
            // Decrypt signing certificate's private key
            byte[] signingUserKey = userKeyService.getUserKey(signingCert.getSignedBy().getId());
            java.security.PrivateKey signingPrivateKey = encryptionService.decryptPrivateKey(
                Base64.getDecoder().decode(signingCert.getEncryptedPrivateKey()),
                Base64.getDecoder().decode(signingCert.getEncryptionIV()),
                Base64.getDecoder().decode(signingCert.getEncryptionTag()),
                Base64.getEncoder().encodeToString(signingUserKey)
            );
            
            // Parse signing certificate's public key
            java.security.PublicKey signingPublicKey = parsePublicKeyFromPEM(signingCert.getPublicKey());
            
            // Generate end-entity certificate
            x509Certificate = certificateGeneratorService.generateEndEntityCertificate(
                keyPair,
                subjectDN,
                issuerDN,
                signingPrivateKey,
                signingPublicKey,
                validityDays,
                keyUsage,
                null, // extendedKeyUsage
                null, // subjectAlternativeNames
                null  // crlDistributionPoint
            );
        }
        
        return x509Certificate;
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



    /**
     * Converts certificate to DTO with status - matches other back-end's CertificateResponse.CreateDto logic.
     */
    private CertificateDTO convertToDTOWithStatus(Certificate certificate, String status) {
        CertificateDTO dto = convertToDTO(certificate);
        // Add status information if needed
        return dto;
    }

}
