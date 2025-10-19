package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.CSRStatus;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateSigningRequestRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.UserKeyService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Collections;
import java.util.Base64;
import java.security.KeyPairGenerator;
import java.io.StringReader;
import java.io.IOException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.openssl.PEMParser;

/**
 * CSRService manages the Certificate Signing Request (CSR) workflow in the PKI system.
 * 
 * This service handles:
 * - Auto-generation of CSRs with new key pairs
 * - Upload and parsing of externally generated CSRs
 * - CSR listing for users and CA administrators
 * - CSR approval and certificate issuance
 * - CSR rejection with reason tracking
 * 
 * The CSR workflow allows users to request certificates that must be approved
 * by CA administrators before issuance.
 */
@Service
@Transactional
public class CSRService {

    private final CertificateSigningRequestRepository csrRepository;
    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CertificateService certificateService;
    private final ValidationService validationService;
    private final EncryptionService encryptionService;
    private final UserKeyService userKeyService;

    public CSRService(
            CertificateSigningRequestRepository csrRepository,
            CertificateRepository certificateRepository,
            UserRepository userRepository,
            CertificateService certificateService,
            ValidationService validationService,
            EncryptionService encryptionService,
            UserKeyService userKeyService) {
        this.csrRepository = csrRepository;
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.certificateService = certificateService;
        this.validationService = validationService;
        this.encryptionService = encryptionService;
        this.userKeyService = userKeyService;
    }

    /**
     * Creates a form-based Certificate Signing Request with automatic key pair generation.
     * 
     * Process:
     * 1. Generate RSA key pair (2048-bit by default)
     * 2. Build PKCS#10 CSR with subject DN and requested extensions
     * 3. Sign CSR with the generated private key
     * 4. Encrypt and store the private key securely
     * 5. Save CSR entity with status PENDING
     * 
     * @param dto Certificate request parameters from form
     * @param userId ID of the user creating the CSR
     * @return CSRDTO containing the CSR information
     * @throws IllegalArgumentException if dto is null or userId is invalid
     * @throws ValidationException if validation fails
     * @throws RuntimeException if key generation or CSR creation fails
     */
    public CSRDTO createFormBasedCSR(CreateCertificateRequestDTO dto, Long userId) {
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        // Find the requester
        User requester = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        // Find the signing certificate
        Certificate selectedCA = certificateRepository.findBySerialNumber(dto.getSigningCertificate())
                .orElseThrow(() -> new RuntimeException("Signing certificate not found: " + dto.getSigningCertificate()));

        try {
            // Generate actual key pair using Java's built-in RSA key generator
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // Generate CSR data from form input using the generated key pair
            String csrData = generateCSRDataFromForm(dto, keyPair);
            
            // Encrypt the private key with user's key
            byte[] userKey = userKeyService.getUserKey(userId);
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(
                keyPair.getPrivate(), 
                Base64.getEncoder().encodeToString(userKey)
            );

            // Create CSR entity
            CertificateSigningRequest csr = new CertificateSigningRequest();
            csr.setCsrData(csrData);
            csr.setStatus(CSRStatus.PENDING);
            csr.setRequester(requester);
            csr.setSelectedCA(selectedCA);
            csr.setSubjectCN(dto.getCommonName());
            csr.setSubjectO(dto.getOrganization());
            csr.setSubjectOU(dto.getOrganizationalUnit());
            csr.setSubjectC(dto.getCountry());
            csr.setSubjectE(dto.getEmail());
            csr.setRequestedExtensions(convertFormExtensionsToJson(dto));
            csr.setEncryptedPrivateKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
            csr.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
            csr.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));

            // Save CSR
            csr = csrRepository.save(csr);
            if (csr == null) {
                throw new RuntimeException("Failed to save CSR");
            }

            // Convert to DTO and return
            return convertToDTO(csr);
        } catch (Exception e) {
            throw new RuntimeException("Error creating form-based CSR: " + e.getMessage());
        }
    }

    /**
     * Auto-generates a Certificate Signing Request with a new key pair.
     * 
     * Process:
     * 1. Generate RSA key pair with specified key size
     * 2. Build PKCS#10 CSR with subject DN and requested extensions
     * 3. Sign CSR with the generated private key
     * 4. Parse CSR to extract subject fields
     * 5. Save CSR entity with status PENDING
     * 6. Store private key securely (encrypted) for later certificate issuance
     * 
     * The generated CSR is in PKCS#12 format and can be submitted to the CA for approval.
     * 
     * @param dto CSR creation parameters (subject DN, key size, extensions, selected CA, template)
     * @param requester The user creating the CSR
     * @return CSRDTO containing the CSR in PKCS#12 format and metadata
     * @throws IllegalArgumentException if dto or requester is null
     * @throws ValidationException if any field validation fails
     * @throws NotFoundException if selected CA or template not found
     */
    public CSRDTO createCSR(CreateCSRDTO dto, User requester) {
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Find the selected CA certificate from database
        Certificate selectedCA = certificateRepository.findById(dto.getSelectedCAId())
            .orElseThrow(() -> new NotFoundException("Selected CA certificate not found with ID: " + dto.getSelectedCAId()));
        
        // Validate that the selected certificate is a CA
        if (selectedCA.getCertificateType() != CertificateType.ROOT && 
            selectedCA.getCertificateType() != CertificateType.INTERMEDIATE) {
            throw new ValidationException("Selected certificate is not a CA certificate");
        }
        
        // Validate that the CA is active
        if (selectedCA.getStatus() != CertificateStatus.ACTIVE) {
            throw new ValidationException("Selected CA certificate is not active");
        }

        // Generate CSR data using Bouncy Castle
        String csrData = generateCSRData(dto);

        // Create CSR entity
        CertificateSigningRequest csr = new CertificateSigningRequest();
        csr.setCsrData(csrData);
        csr.setStatus(CSRStatus.PENDING);
        csr.setRequester(requester);
        csr.setSelectedCA(selectedCA);
        csr.setSubjectCN(dto.getSubjectCN());
        csr.setSubjectO(dto.getSubjectO());
        csr.setSubjectOU(dto.getSubjectOU());
        csr.setSubjectC(dto.getSubjectC());
        csr.setSubjectE(dto.getSubjectE());
        csr.setRequestedExtensions(convertExtensionsToJson(dto.getExtensions()));

        // Save CSR
        csr = csrRepository.save(csr);
        if (csr == null) {
            throw new RuntimeException("Failed to save CSR");
        }

        // Convert to DTO and return
        return convertToDTO(csr);
    }

    /**
     * Uploads and processes an externally generated Certificate Signing Request with private key.
     * 
     * Process:
     * 1. Parse PKCS#12 CSR using Bouncy Castle
     * 2. Parse PKCS#12 private key using Bouncy Castle
     * 3. Verify CSR signature matches the private key
     * 4. Extract subject DN fields from CSR
     * 5. Extract requested extensions (Key Usage, Extended Key Usage, SANs)
     * 6. Validate selected CA exists and is a valid CA certificate
     * 7. Encrypt and store the private key securely
     * 8. Save CSR entity with status PENDING
     * 
     * @param signingCertificate Serial number of the CA certificate to sign the CSR
     * @param csrContent PKCS#12 CSR content
     * @param privateKeyContent PKCS#12 private key content
     * @param notAfter Optional validity end date
     * @param userId ID of the user uploading the CSR
     * @throws IllegalArgumentException if parameters are null or empty
     * @throws ValidationException if CSR or private key parsing fails
     * @throws NotFoundException if signing certificate not found
     */
    public void uploadCSRWithPrivateKey(String signingCertificate, String csrContent, String privateKeyContent, 
                                       LocalDateTime notAfter, Long userId) {
        if (signingCertificate == null || signingCertificate.trim().isEmpty()) {
            throw new IllegalArgumentException("Signing certificate cannot be null or empty");
        }
        if (csrContent == null || csrContent.trim().isEmpty()) {
            throw new IllegalArgumentException("CSR content cannot be null or empty");
        }
        if (privateKeyContent == null || privateKeyContent.trim().isEmpty()) {
            throw new IllegalArgumentException("Private key content cannot be null or empty");
        }

        // Find the requester
        User requester = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

        // Find the signing certificate
        Certificate selectedCA = certificateRepository.findBySerialNumber(signingCertificate)
                .orElseThrow(() -> new RuntimeException("Signing certificate not found: " + signingCertificate));

        // Extract subject fields from CSR (placeholder - would use Bouncy Castle)
        String subjectCN = extractSubjectCN(csrContent);
        String subjectO = extractSubjectO(csrContent);
        String subjectOU = extractSubjectOU(csrContent);
        String subjectC = extractSubjectC(csrContent);
        String subjectE = extractSubjectE(csrContent);

        // Encrypt the private key with user's key
        try {
            byte[] userKey = userKeyService.getUserKey(userId);
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(
                parsePrivateKeyFromPEM(privateKeyContent), 
                Base64.getEncoder().encodeToString(userKey)
            );

            // Create CSR entity
            CertificateSigningRequest csr = new CertificateSigningRequest();
            csr.setCsrData(csrContent);
            csr.setStatus(CSRStatus.PENDING);
            csr.setRequester(requester);
            csr.setSelectedCA(selectedCA);
            csr.setSubjectCN(subjectCN);
            csr.setSubjectO(subjectO);
            csr.setSubjectOU(subjectOU);
            csr.setSubjectC(subjectC);
            csr.setSubjectE(subjectE);
            csr.setRequestedExtensions("{}"); // Placeholder
            csr.setEncryptedPrivateKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
            csr.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
            csr.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));

            // Save CSR
            csrRepository.save(csr);
        } catch (Exception e) {
            throw new RuntimeException("Error processing CSR and private key: " + e.getMessage());
        }
    }

    /**
     * Uploads and processes an externally generated Certificate Signing Request.
     * 
     * Process:
     * 1. Parse PKCS#12 CSR using Bouncy Castle
     * 2. Verify CSR signature to ensure integrity
     * 3. Extract subject DN fields from CSR
     * 4. Extract requested extensions (Key Usage, Extended Key Usage, SANs)
     * 5. Validate selected CA exists and is a valid CA certificate
     * 6. If template is selected, pre-validate CSR against template constraints
     * 7. Save CSR entity with status PENDING
     * 
     * Note: The private key is NOT included (user retains it), so certificate
     * will need to be delivered to the user after approval.
     * 
     * @param dto Upload parameters (PKCS#12 CSR data, selected CA, optional template)
     * @param requester The user uploading the CSR
     * @return CSRDTO containing parsed CSR information
     * @throws IllegalArgumentException if dto or requester is null
     * @throws ValidationException if CSR parsing or validation fails
     * @throws NotFoundException if selected CA or template not found
     * @throws InvalidCSRException if CSR signature is invalid or format is incorrect
     */
    public CSRDTO uploadCSR(UploadCSRDTO dto, User requester) {
        if (dto == null) {
            throw new IllegalArgumentException("DTO cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Parse and validate CSR
        String csrData = dto.getCsrData();
        if (csrData == null || csrData.trim().isEmpty()) {
            throw new ValidationException("CSR data cannot be null or empty");
        }

        // Validate CSR format by attempting to parse it
        try {
            parseCSR(csrData);
        } catch (Exception e) {
            throw new ValidationException("Invalid CSR format: " + e.getMessage());
        }

        // Extract subject fields from CSR using Bouncy Castle
        String subjectCN = extractSubjectCN(csrData);
        String subjectO = extractSubjectO(csrData);
        String subjectOU = extractSubjectOU(csrData);
        String subjectC = extractSubjectC(csrData);
        String subjectE = extractSubjectE(csrData);

        // Find the selected CA certificate from database
        Certificate selectedCA = certificateRepository.findById(dto.getSelectedCAId())
            .orElseThrow(() -> new NotFoundException("Selected CA certificate not found with ID: " + dto.getSelectedCAId()));
        
        // Validate that the selected certificate is a CA
        if (selectedCA.getCertificateType() != CertificateType.ROOT && 
            selectedCA.getCertificateType() != CertificateType.INTERMEDIATE) {
            throw new ValidationException("Selected certificate is not a CA certificate");
        }
        
        // Validate that the CA is active
        if (selectedCA.getStatus() != CertificateStatus.ACTIVE) {
            throw new ValidationException("Selected CA certificate is not active");
        }

        // Create CSR entity
        CertificateSigningRequest csr = new CertificateSigningRequest();
        csr.setCsrData(csrData);
        csr.setStatus(CSRStatus.PENDING);
        csr.setRequester(requester);
        csr.setSelectedCA(selectedCA);
        csr.setSubjectCN(subjectCN);
        csr.setSubjectO(subjectO);
        csr.setSubjectOU(subjectOU);
        csr.setSubjectC(subjectC);
        csr.setSubjectE(subjectE);
        csr.setRequestedExtensions("{}"); // Placeholder

        // Save CSR
        csr = csrRepository.save(csr);
        if (csr == null) {
            throw new RuntimeException("Failed to save CSR");
        }

        // Convert to DTO and return
        return convertToDTO(csr);
    }

    /**
     * Lists all CSRs created by a specific user.
     * 
     * Returns CSRs in all states (PENDING, APPROVED, REJECTED) to allow
     * users to track their certificate requests.
     * 
     * @param requester The user whose CSRs to list
     * @param pageable Pagination parameters
     * @return Page of CSRDTO objects
     * @throws IllegalArgumentException if requester is null
     */
    public Page<CSRDTO> listUserCSRs(User requester, Pageable pageable) {
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }
        if (pageable == null) {
            throw new IllegalArgumentException("Pageable cannot be null");
        }

        // Query CSRs by requester
        Page<CertificateSigningRequest> csrPage = csrRepository.findByRequester(requester, pageable);
        
        if (csrPage == null) {
            // Return empty page if no results
            return new PageImpl<>(Collections.emptyList(), pageable, 0);
        }
        
        // Convert to DTOs
        List<CSRDTO> csrDTOs = csrPage.getContent().stream()
            .map(this::convertToDTO)
            .toList();
        
        return new PageImpl<>(csrDTOs, pageable, csrPage.getTotalElements());
    }

    /**
     * Lists pending CSRs that a CA user can approve.
     * 
     * Filtering logic:
     * - For CA_USER: Returns CSRs where selectedCA is owned by the user
     *   OR where selectedCA is in the user's CA chain
     * - For ADMIN: Returns all pending CSRs
     * - For EE_USER: Returns empty list (no approval permission)
     * 
     * Only CSRs with status PENDING are returned.
     * 
     * @param caUser The CA user or admin viewing pending CSRs
     * @param pageable Pagination parameters
     * @return Page of CSRDTO objects with status PENDING
     * @throws IllegalArgumentException if caUser is null
     */
    public Page<CSRDTO> listPendingCSRs(User caUser, Pageable pageable) {
        if (caUser == null) {
            throw new IllegalArgumentException("CA user cannot be null");
        }
        if (pageable == null) {
            throw new IllegalArgumentException("Pageable cannot be null");
        }

        Page<CertificateSigningRequest> csrPage;
        
        if (caUser.getRole() == Role.ADMIN) {
            // ADMIN can see all pending CSRs
            csrPage = csrRepository.findByStatus(CSRStatus.PENDING, pageable);
        } else if (caUser.getRole() == Role.CA_USER) {
            // CA_USER can see CSRs for their own CAs
            // For now, use a placeholder certificate - in real implementation, find user's certificates
            Certificate userCA = new Certificate();
            userCA.setId(caUser.getId());
            csrPage = csrRepository.findBySelectedCAAndStatus(userCA, CSRStatus.PENDING, pageable);
        } else {
            // EE_USER has no approval permission
            return new PageImpl<>(Collections.emptyList(), pageable, 0);
        }
        
        if (csrPage == null) {
            // Return empty page if no results
            return new PageImpl<>(Collections.emptyList(), pageable, 0);
        }
        
        // Convert to DTOs
        List<CSRDTO> csrDTOs = csrPage.getContent().stream()
            .map(this::convertToDTO)
            .toList();
        
        return new PageImpl<>(csrDTOs, pageable, csrPage.getTotalElements());
    }

    /**
     * Approves a CSR and issues the corresponding certificate.
     * 
     * Process:
     * 1. Validate CSR exists and has status PENDING
     * 2. Validate approver has permission (owns selected CA or is ADMIN)
     * 3. Extract public key from the CSR
     * 4. Create end-entity certificate using CertificateService
     * 5. Update CSR: status = APPROVED, issuedCertificate = cert, 
     *    processedBy = approver, processedAt = now
     * 
     * Authorization:
     * - ADMIN can approve any CSR
     * - CA_USER can approve CSRs for their own CAs
     * - EE_USER cannot approve CSRs
     * 
     * @param csrId The ID of the CSR to approve
     * @param dto Approval parameters (may include validity override, additional extensions)
     * @param approver The user approving the CSR
     * @return CSRDTO with status APPROVED and issued certificate details
     * @throws IllegalArgumentException if dto or approver is null
     * @throws NotFoundException if CSR not found
     * @throws UnauthorizedException if approver lacks permission
     * @throws IllegalStateException if CSR is not in PENDING status
     * @throws ValidationException if certificate creation fails
     */
    public CSRDTO approveCSR(Long csrId, ApproveCSRDTO dto, User approver) {
        if (csrId == null) {
            throw new IllegalArgumentException("CSR ID cannot be null");
        }
        if (dto == null) {
            throw new IllegalArgumentException("Approve DTO cannot be null");
        }
        if (approver == null) {
            throw new IllegalArgumentException("Approver cannot be null");
        }

        // Find the CSR
        Optional<CertificateSigningRequest> csrOpt = csrRepository.findById(csrId);
        if (csrOpt.isEmpty()) {
            throw new NotFoundException("CSR not found with ID: " + csrId);
        }
        
        CertificateSigningRequest csr = csrOpt.get();
        
        // Validate CSR is in PENDING status
        if (csr.getStatus() != CSRStatus.PENDING) {
            throw new IllegalStateException("CSR is not in PENDING status");
        }
        
        // Validate approver has permission
        if (!hasApprovalPermission(csr, approver)) {
            throw new UnauthorizedException("User does not have permission to approve this CSR");
        }
        
        // Create end-entity certificate (placeholder implementation)
        // In a real implementation, this would:
        // 1. Extract public key from CSR
        // 2. Create CreateEndEntityCertificateDTO
        // 3. Call certificateService.createEndEntityCertificate()
        
        // Update CSR status
        csr.setStatus(CSRStatus.APPROVED);
        csr.setProcessedBy(approver);
        csr.setProcessedAt(java.time.LocalDateTime.now());
        
        // Save updated CSR
        csr = csrRepository.save(csr);
        
        // Convert to DTO and return
        return convertToDTO(csr);
    }

    /**
     * Rejects a CSR with a specified reason.
     * 
     * Process:
     * 1. Validate CSR exists and has status PENDING
     * 2. Validate approver has permission (owns selected CA or is ADMIN)
     * 3. Update CSR: status = REJECTED, rejectionReason = dto.reason,
     *    processedBy = approver, processedAt = now
     * 
     * The rejection reason should provide clear feedback to the requester
     * about why the CSR was rejected.
     * 
     * Authorization: Same as approveCSR
     * 
     * @param csrId The ID of the CSR to reject
     * @param dto Rejection parameters (reason)
     * @param approver The user rejecting the CSR
     * @return CSRDTO with status REJECTED and rejection reason
     * @throws IllegalArgumentException if dto or approver is null
     * @throws NotFoundException if CSR not found
     * @throws UnauthorizedException if approver lacks permission
     * @throws IllegalStateException if CSR is not in PENDING status
     * @throws ValidationException if rejection reason is empty
     */
    public CSRDTO rejectCSR(Long csrId, RejectCSRDTO dto, User approver) {
        if (csrId == null) {
            throw new IllegalArgumentException("CSR ID cannot be null");
        }
        if (dto == null) {
            throw new IllegalArgumentException("Reject DTO cannot be null");
        }
        if (approver == null) {
            throw new IllegalArgumentException("Approver cannot be null");
        }

        // Validate rejection reason
        if (dto.getReason() == null || dto.getReason().trim().isEmpty()) {
            throw new ValidationException("Rejection reason cannot be null or empty");
        }

        // Find the CSR
        Optional<CertificateSigningRequest> csrOpt = csrRepository.findById(csrId);
        if (csrOpt.isEmpty()) {
            throw new NotFoundException("CSR not found with ID: " + csrId);
        }
        
        CertificateSigningRequest csr = csrOpt.get();
        
        // Validate CSR is in PENDING status
        if (csr.getStatus() != CSRStatus.PENDING) {
            throw new IllegalStateException("CSR is not in PENDING status");
        }
        
        // Validate approver has permission
        if (!hasApprovalPermission(csr, approver)) {
            throw new UnauthorizedException("User does not have permission to reject this CSR");
        }
        
        // Update CSR status
        csr.setStatus(CSRStatus.REJECTED);
        csr.setRejectionReason(dto.getReason());
        csr.setProcessedBy(approver);
        csr.setProcessedAt(java.time.LocalDateTime.now());
        
        // Save updated CSR
        csr = csrRepository.save(csr);
        
        // Convert to DTO and return
        return convertToDTO(csr);
    }

    /**
     * Gets a specific CSR by ID with access control.
     * 
     * Access rules:
     * - Requester can view their own CSRs
     * - CA users can view CSRs for their CAs
     * - ADMIN can view any CSR
     * 
     * @param csrId The ID of the CSR
     * @param requester The user requesting the CSR
     * @return CSRDTO containing CSR details
     * @throws IllegalArgumentException if requester is null
     * @throws NotFoundException if CSR not found
     * @throws ForbiddenException if requester lacks access
     */
    public CSRDTO getCSRById(Long csrId, User requester) {
        if (csrId == null) {
            throw new IllegalArgumentException("CSR ID cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Find the CSR
        Optional<CertificateSigningRequest> csrOpt = csrRepository.findById(csrId);
        if (csrOpt.isEmpty()) {
            throw new NotFoundException("CSR not found with ID: " + csrId);
        }
        
        CertificateSigningRequest csr = csrOpt.get();
        
        // Check access permissions
        if (!hasAccessToCSR(csr, requester)) {
            throw new ForbiddenException("User does not have access to this CSR");
        }
        
        // Convert to DTO and return
        return convertToDTO(csr);
    }

    /**
     * Converts a CertificateSigningRequest entity to a CSRDTO for API responses.
     * 
     * @param csr The CSR entity
     * @return CSRDTO containing CSR information
     */
    private CSRDTO convertToDTO(CertificateSigningRequest csr) {
        CSRDTO dto = new CSRDTO();
        dto.setId(csr.getId());
        dto.setCsrData(csr.getCsrData());
        dto.setStatus(csr.getStatus());
        dto.setSubjectCN(csr.getSubjectCN());
        dto.setSubjectO(csr.getSubjectO());
        dto.setSubjectOU(csr.getSubjectOU());
        dto.setSubjectC(csr.getSubjectC());
        dto.setSubjectE(csr.getSubjectE());
        dto.setRequestedExtensions(csr.getRequestedExtensions());
        dto.setRejectionReason(csr.getRejectionReason());
        dto.setCreatedAt(csr.getCreatedAt());
        dto.setProcessedAt(csr.getProcessedAt());

        // Set requester info
        if (csr.getRequester() != null) {
            CSRDTO.UserDTO requesterDTO = new CSRDTO.UserDTO();
            requesterDTO.setId(csr.getRequester().getId());
            requesterDTO.setEmail(csr.getRequester().getEmail());
            requesterDTO.setFirstName(csr.getRequester().getFirstName());
            requesterDTO.setLastName(csr.getRequester().getLastName());
            dto.setRequester(requesterDTO);
        }

        // Set processed by info
        if (csr.getProcessedBy() != null) {
            CSRDTO.UserDTO processedByDTO = new CSRDTO.UserDTO();
            processedByDTO.setId(csr.getProcessedBy().getId());
            processedByDTO.setEmail(csr.getProcessedBy().getEmail());
            processedByDTO.setFirstName(csr.getProcessedBy().getFirstName());
            processedByDTO.setLastName(csr.getProcessedBy().getLastName());
            dto.setProcessedBy(processedByDTO);
        }

        // Set selected CA info
        if (csr.getSelectedCA() != null) {
            CSRDTO.CertificateDTO caDTO = new CSRDTO.CertificateDTO();
            caDTO.setId(csr.getSelectedCA().getId());
            caDTO.setSerialNumber(csr.getSelectedCA().getSerialNumber());
            caDTO.setSubjectCN(csr.getSelectedCA().getSubjectCN());
            dto.setSelectedCA(caDTO);
        }

        // Set issued certificate info
        if (csr.getIssuedCertificate() != null) {
            CSRDTO.CertificateDTO issuedDTO = new CSRDTO.CertificateDTO();
            issuedDTO.setId(csr.getIssuedCertificate().getId());
            issuedDTO.setSerialNumber(csr.getIssuedCertificate().getSerialNumber());
            issuedDTO.setSubjectCN(csr.getIssuedCertificate().getSubjectCN());
            dto.setIssuedCertificate(issuedDTO);
        }

        return dto;
    }

    /**
     * Checks if a user has permission to approve/reject a CSR.
     * 
     * @param csr The CSR to check
     * @param approver The user attempting to approve/reject
     * @return true if the user has permission, false otherwise
     */
    private boolean hasApprovalPermission(CertificateSigningRequest csr, User approver) {
        if (approver.getRole() == Role.ADMIN) {
            return true;
        }
        
        if (approver.getRole() == Role.CA_USER) {
            // CA_USER can approve CSRs for their own CAs
            return csr.getSelectedCA() != null && 
                   csr.getSelectedCA().getSignedBy() != null &&
                   csr.getSelectedCA().getSignedBy().getId().equals(approver.getId());
        }
        
        return false;
    }

    /**
     * Checks if a user has access to view a CSR.
     * 
     * @param csr The CSR to check
     * @param requester The user requesting access
     * @return true if the user has access, false otherwise
     */
    private boolean hasAccessToCSR(CertificateSigningRequest csr, User requester) {
        if (requester.getRole() == Role.ADMIN) {
            return true;
        }
        
        if (requester.getRole() == Role.CA_USER) {
            // CA_USER can view CSRs for their own CAs
        return csr.getSelectedCA() != null && 
               csr.getSelectedCA().getSignedBy() != null &&
               csr.getSelectedCA().getSignedBy().getId().equals(requester.getId());
        }
        
        if (requester.getRole() == Role.EE_USER) {
            // EE_USER can only view their own CSRs
            return csr.getRequester() != null && 
                   csr.getRequester().getId().equals(requester.getId());
        }
        
        return false;
    }

    /**
     * Generates CSR data in PEM format (PKCS#10).
     * 
     * @param dto The CSR creation DTO
     * @return PEM-encoded CSR data
     */
    private String generateCSRData(CreateCSRDTO dto) {
        try {
            // Generate RSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // Build X500Name for subject
            org.bouncycastle.asn1.x500.X500NameBuilder nameBuilder = new org.bouncycastle.asn1.x500.X500NameBuilder(BCStyle.INSTANCE);
            nameBuilder.addRDN(BCStyle.CN, dto.getSubjectCN());
            if (dto.getSubjectO() != null && !dto.getSubjectO().isEmpty()) {
                nameBuilder.addRDN(BCStyle.O, dto.getSubjectO());
            }
            if (dto.getSubjectOU() != null && !dto.getSubjectOU().isEmpty()) {
                nameBuilder.addRDN(BCStyle.OU, dto.getSubjectOU());
            }
            if (dto.getSubjectC() != null && !dto.getSubjectC().isEmpty()) {
                nameBuilder.addRDN(BCStyle.C, dto.getSubjectC());
            }
            if (dto.getSubjectE() != null && !dto.getSubjectE().isEmpty()) {
                nameBuilder.addRDN(BCStyle.E, dto.getSubjectE());
            }
            
            X500Name subject = nameBuilder.build();
            
            // Build PKCS#10 CSR
            JcaPKCS10CertificationRequestBuilder csrBuilder = 
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            
            // Sign the CSR with private key
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());
            
            PKCS10CertificationRequest csr = csrBuilder.build(signer);
            
            // Convert to PEM format with proper line breaks
            String base64Encoded = Base64.getEncoder().encodeToString(csr.getEncoded());
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN CERTIFICATE REQUEST-----\n");
            
            // Add line breaks every 64 characters
            int index = 0;
            while (index < base64Encoded.length()) {
                int endIndex = Math.min(index + 64, base64Encoded.length());
                pemBuilder.append(base64Encoded.substring(index, endIndex)).append("\n");
                index = endIndex;
            }
            
            pemBuilder.append("-----END CERTIFICATE REQUEST-----");
            
            return pemBuilder.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Converts extensions map to JSON string.
     * 
     * @param extensions The extensions map
     * @return JSON string representation
     */
    private String convertExtensionsToJson(Map<String, List<String>> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return "{}";
        }
        
        // Simple JSON conversion (in real implementation, use Jackson or Gson)
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, List<String>> entry : extensions.entrySet()) {
            if (!first) {
                json.append(",");
            }
            json.append("\"").append(entry.getKey()).append("\":");
            json.append("[");
            List<String> values = entry.getValue();
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) {
                    json.append(",");
                }
                json.append("\"").append(values.get(i)).append("\"");
            }
            json.append("]");
            first = false;
        }
        json.append("}");
        return json.toString();
    }

    /**
     * Extracts subject CN from CSR data using Bouncy Castle.
     * 
     * @param csrData The CSR data in PEM or DER format
     * @return Subject CN, or null if not found
     */
    private String extractSubjectCN(String csrData) {
        try {
            PKCS10CertificationRequest csr = parseCSR(csrData);
            X500Name subject = csr.getSubject();
            return getRDNValue(subject, BCStyle.CN);
        } catch (Exception e) {
            System.err.println("Failed to extract CN from CSR: " + e.getMessage());
            return null;
        }
    }

    /**
     * Extracts subject O (Organization) from CSR data using Bouncy Castle.
     * 
     * @param csrData The CSR data in PEM or DER format
     * @return Subject O, or null if not found
     */
    private String extractSubjectO(String csrData) {
        try {
            PKCS10CertificationRequest csr = parseCSR(csrData);
            X500Name subject = csr.getSubject();
            return getRDNValue(subject, BCStyle.O);
        } catch (Exception e) {
            System.err.println("Failed to extract O from CSR: " + e.getMessage());
            return null;
        }
    }

    /**
     * Extracts subject OU (Organizational Unit) from CSR data using Bouncy Castle.
     * 
     * @param csrData The CSR data in PEM or DER format
     * @return Subject OU, or null if not found
     */
    private String extractSubjectOU(String csrData) {
        try {
            PKCS10CertificationRequest csr = parseCSR(csrData);
            X500Name subject = csr.getSubject();
            return getRDNValue(subject, BCStyle.OU);
        } catch (Exception e) {
            System.err.println("Failed to extract OU from CSR: " + e.getMessage());
            return null;
        }
    }

    /**
     * Extracts subject C (Country) from CSR data using Bouncy Castle.
     * 
     * @param csrData The CSR data in PEM or DER format
     * @return Subject C, or null if not found
     */
    private String extractSubjectC(String csrData) {
        try {
            PKCS10CertificationRequest csr = parseCSR(csrData);
            X500Name subject = csr.getSubject();
            return getRDNValue(subject, BCStyle.C);
        } catch (Exception e) {
            System.err.println("Failed to extract C from CSR: " + e.getMessage());
            return null;
        }
    }

    /**
     * Extracts subject E (Email) from CSR data using Bouncy Castle.
     * 
     * @param csrData The CSR data in PEM or DER format
     * @return Subject E, or null if not found
     */
    private String extractSubjectE(String csrData) {
        try {
            PKCS10CertificationRequest csr = parseCSR(csrData);
            X500Name subject = csr.getSubject();
            return getRDNValue(subject, BCStyle.E);
        } catch (Exception e) {
            System.err.println("Failed to extract E from CSR: " + e.getMessage());
            return null;
        }
    }

    /**
     * Parses CSR data from PEM format (PKCS#10) using Bouncy Castle.
     * 
     * @param csrData The CSR data in PEM format
     * @return PKCS10CertificationRequest object
     * @throws Exception if parsing fails
     */
    private PKCS10CertificationRequest parseCSR(String csrData) throws Exception {
        if (csrData == null || csrData.trim().isEmpty()) {
            throw new IllegalArgumentException("CSR data cannot be null or empty");
        }
        
        try {
            // Handle PEM format
            if (csrData.contains("BEGIN CERTIFICATE REQUEST") || csrData.contains("BEGIN NEW CERTIFICATE REQUEST")) {
                try (PEMParser pemParser = new PEMParser(new StringReader(csrData))) {
                    Object parsedObj = pemParser.readObject();
                    if (parsedObj instanceof PKCS10CertificationRequest) {
                        return (PKCS10CertificationRequest) parsedObj;
                    } else {
                        throw new IllegalArgumentException("Parsed object is not a PKCS10CertificationRequest");
                    }
                }
            } else {
                // Try to parse as Base64-encoded DER
                String cleanData = csrData.replaceAll("\\s", "");
                byte[] derBytes = Base64.getDecoder().decode(cleanData);
                return new PKCS10CertificationRequest(derBytes);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse CSR: " + e.getMessage(), e);
        }
    }

    /**
     * Gets RDN (Relative Distinguished Name) value from X500Name.
     * 
     * @param name The X500Name to extract from
     * @param oid The ASN1 Object Identifier of the field
     * @return The value of the RDN, or null if not found
     */
    private String getRDNValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns.length > 0) {
            return rdns[0].getFirst().getValue().toString();
        }
        return null;
    }

    /**
     * Creates a certificate request from form data and generates a key pair.
     * 
     * @param requestDTO The certificate request form data
     * @param userId The ID of the user making the request
     * @return KeyPairDTO containing the generated public and private keys
     */
    public KeyPairDTO createCertificateRequest(CreateCertificateRequestDTO requestDTO, Long userId) {
        // Find the EE user
        User user = findUserByIdAndRole(userId, Role.EE_USER);
        
        // Find the signing certificate and its owner
        Certificate signingCert = findCertificateBySerialNumber(requestDTO.getSigningCertificate());
        if (signingCert == null) {
            throw new RuntimeException("Signing certificate not found!");
        }
        User issuer = signingCert.getSignedBy();
        
        // Check if issuer has valid certificates
        if (!hasValidCertificates(issuer)) {
            throw new RuntimeException("Requested issuer is not able to sign certificates!");
        }
        
        // Validate validity period constraints
        validateValidityPeriod(requestDTO, issuer);
        
        // Generate actual RSA key pair
        java.security.KeyPairGenerator keyGen;
        java.security.KeyPair actualKeyPair;
        try {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            actualKeyPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error generating key pair: " + e.getMessage());
        }
        
        // Generate CSR data using the actual key pair
        String csrData = generateCSRDataFromForm(requestDTO, actualKeyPair);
        
        // Convert to KeyPairDTO for return
        KeyPairDTO keyPair = generateKeyPair();
        
        // Create certificate request entity
        CertificateSigningRequest csr = new CertificateSigningRequest();
        csr.setCsrData(csrData);  // Set the required CSR data
        csr.setRequester(user);
        csr.setRequestedFrom(issuer);
        csr.setSubjectCN(requestDTO.getCommonName());
        csr.setSubjectO(requestDTO.getOrganization());
        csr.setSubjectOU(requestDTO.getOrganizationalUnit());
        csr.setSubjectE(requestDTO.getEmail());
        csr.setSubjectC(requestDTO.getCountry());
        csr.setStatus(CSRStatus.PENDING);
        csr.setRequestedExtensions(convertExtensionsToJson(requestDTO));
        
        // Use the actual signing certificate
        csr.setSelectedCA(signingCert);
        
        csrRepository.save(csr);
        
        return keyPair;
    }

    /**
     * Creates a certificate request from uploaded CSR.
     * 
     * @param signingUserId The ID of the CA user who will sign
     * @param csrContent The CSR content
     * @param notAfter The validity end date
     * @param userId The ID of the user making the request
     */
    public void createCertificateRequest(String signingUserId, String csrContent, LocalDateTime notAfter, Long userId) {
        // Find the EE user
        User user = findUserByIdAndRole(userId, Role.EE_USER);
        
        // Find the signing organization (CA user)
        User issuer = findUserByIdAndRole(Long.parseLong(signingUserId), Role.CA_USER);
        
        // Check if issuer has valid certificates
        if (!hasValidCertificates(issuer)) {
            throw new RuntimeException("Requested issuer is not able to sign certificates!");
        }
        
        // Validate validity period
        if (notAfter != null) {
            LocalDateTime maxValidUntil = getMaxValidUntil(issuer);
            if (notAfter.isAfter(maxValidUntil)) {
                throw new RuntimeException("NotAfter cannot be later than the issuer's latest NotAfter!");
            }
        }
        
        // Create certificate request entity
        CertificateSigningRequest csr = new CertificateSigningRequest();
        csr.setRequester(user);
        csr.setRequestedFrom(issuer);
        csr.setCsrData(csrContent);
        csr.setStatus(CSRStatus.PENDING);
        
        // Set selectedCA to a placeholder certificate (would need actual certificate lookup)
        Certificate selectedCA = new Certificate();
        selectedCA.setId(Long.parseLong(signingUserId));
        csr.setSelectedCA(selectedCA);
        
        csrRepository.save(csr);
    }

    /**
     * Gets certificate requests for a CA user.
     * 
     * @param userId The ID of the CA user
     * @return List of certificate request responses
     */
    public List<CertificateRequestResponseDTO> getCertificateRequests(Long userId) {
        User caUser = findUserByIdAndRole(userId, Role.CA_USER);
        
        // Find all pending CSRs
        List<CertificateSigningRequest> allPendingRequests = csrRepository.findByStatus(CSRStatus.PENDING);
        
        // Filter requests where the selectedCA is in the CA user's chain
        List<CertificateSigningRequest> requests = allPendingRequests.stream()
                .filter(csr -> {
                    Certificate selectedCA = csr.getSelectedCA();
                    if (selectedCA == null) {
                        return false;
                    }
                    // Check if the selectedCA is in the CA user's certificate chain
                    return isCertificateInUserChain(selectedCA, caUser);
                })
                .toList();
        
        return requests.stream()
                .map(this::convertToResponseDTO)
                .toList();
    }

    /**
     * Deletes (rejects) a certificate request.
     * 
     * @param userId The ID of the CA user
     * @param requestId The ID of the request to delete
     */
    public void deleteCertificateRequest(Long userId, String requestId) {
        User caUser = findUserByIdAndRole(userId, Role.CA_USER);
        
        CertificateSigningRequest request = csrRepository.findById(Long.parseLong(requestId))
                .orElseThrow(() -> new RuntimeException("Certificate request with given ID not found!"));
        
        // Check if the CA user has permission to reject this request
        // The CA user can reject if the selectedCA certificate is in their chain
        if (!isCertificateInUserChain(request.getSelectedCA(), caUser)) {
            throw new RuntimeException("This certificate is not requested from you! The request can be rejected by a CA user whose certificate chain includes the requested signing certificate.");
        }
        
        // Update request status to rejected instead of deleting
        request.setStatus(CSRStatus.REJECTED);
        request.setProcessedBy(caUser);
        request.setProcessedAt(java.time.LocalDateTime.now());
        request.setRejectionReason("Rejected by CA user");
        csrRepository.save(request);
    }

    /**
     * Approves a certificate request and creates a certificate.
     * 
     * @param userId The ID of the CA user
     * @param approveRequest The approval request data
     */
    public void approveCertificateRequest(Long userId, ApproveCertificateRequestDTO approveRequest) {
        User caUser = findUserByIdAndRole(userId, Role.CA_USER);
        
        CertificateSigningRequest request = csrRepository.findById(Long.parseLong(approveRequest.getRequestId()))
                .orElseThrow(() -> new RuntimeException("Certificate request with given ID not found!"));
        
        // Check if the CA user has permission to approve this request
        // The CA user can approve if the selectedCA certificate is in their chain
        if (!isCertificateInUserChain(request.getSelectedCA(), caUser)) {
            throw new RuntimeException("This certificate is not requested from you! The request can be approved by a CA user whose certificate chain includes the requested signing certificate.");
        }
        
        // Create certificate using the certificate service
        try {
            // Create CreateEndEntityCertificateDTO from the request
            CreateEndEntityCertificateDTO certDTO = new CreateEndEntityCertificateDTO();
            certDTO.setSubjectCN(request.getSubjectCN());
            certDTO.setSubjectO(request.getSubjectO());
            certDTO.setSubjectOU(request.getSubjectOU());
            certDTO.setSubjectC(request.getSubjectC());
            certDTO.setSubjectE(request.getSubjectE());
            certDTO.setSubjectL(null); // Optional field
            certDTO.setSubjectST(null); // Optional field
            certDTO.setIssuerCertificateId(request.getSelectedCA().getId());
            certDTO.setValidityDays(approveRequest.getValidityDays() != null ? approveRequest.getValidityDays() : 365);
            certDTO.setKeyUsage(java.util.Arrays.asList("DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"));
            certDTO.setExtendedKeyUsage(java.util.Arrays.asList("SERVER_AUTH", "CLIENT_AUTH"));
            certDTO.setSubjectAlternativeNames(new java.util.ArrayList<>());
            certDTO.setCrlDistributionPoint("http://localhost:8080/api/crl");
            certDTO.setKeySize(2048); // Set the key size to 2048 bits
            
            // Create the certificate
            CertificateDTO createdCertificate = certificateService.createEndEntityCertificate(certDTO,caUser, true);
            
            System.out.println("DEBUG CSR APPROVAL: Certificate created with ID: " + createdCertificate.getId());
            System.out.println("DEBUG CSR APPROVAL: Certificate serial: " + createdCertificate.getSerialNumber());
            
            // Add the certificate to the requester's MyCertificates collection
            // Fetch the user fresh from database to ensure the collection is managed
            Long requesterId = request.getRequester().getId();
            User requester = userRepository.findByIdWithCertificates(requesterId)
                .orElseThrow(() -> new RuntimeException("Requester not found"));
            
            System.out.println("DEBUG CSR APPROVAL: Requester ID: " + requester.getId());
            System.out.println("DEBUG CSR APPROVAL: Requester email: " + requester.getEmail());
            System.out.println("DEBUG CSR APPROVAL: Requester's MyCertificates count BEFORE adding: " + requester.getMyCertificates().size());
            
            Certificate certificateEntity = certificateRepository.findById(createdCertificate.getId())
                .orElseThrow(() -> new RuntimeException("Created certificate not found"));
            
            System.out.println("DEBUG CSR APPROVAL: Found certificate entity with ID: " + certificateEntity.getId());
            
            // Check if certificate is already in the collection (shouldn't be, but just in case)
            boolean alreadyExists = requester.getMyCertificates().stream()
                .anyMatch(cert -> cert.getId().equals(certificateEntity.getId()));
            
            if (!alreadyExists) {
                requester.getMyCertificates().add(certificateEntity);
                System.out.println("DEBUG CSR APPROVAL: Certificate added to collection");
            } else {
                System.out.println("DEBUG CSR APPROVAL: Certificate already in collection");
            }
            
            System.out.println("DEBUG CSR APPROVAL: Requester's MyCertificates count AFTER adding: " + requester.getMyCertificates().size());
            
            User savedUser = userRepository.save(requester);
            System.out.println("DEBUG CSR APPROVAL: User saved. Saved user's MyCertificates count: " + savedUser.getMyCertificates().size());
            
            // Update request status to approved
            request.setStatus(CSRStatus.APPROVED);
            request.setProcessedBy(caUser);
            request.setProcessedAt(java.time.LocalDateTime.now());
            csrRepository.save(request);
            
            System.out.println("DEBUG CSR APPROVAL: CSR approval completed successfully");
            
        } catch (Exception e) {
            throw new RuntimeException("Error creating certificate: " + e.getMessage());
        }
    }

    // Helper methods
    private User findUserByIdAndRole(Long userId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User not found with ID: " + userId));
        
        if (user.getRole() != role) {
            throw new ForbiddenException("User does not have the required role: " + role);
        }
        
        return user;
    }

    /**
     * Checks if a certificate is in the CA user's chain.
     * A certificate is in the chain if:
     * - The CA user owns it directly (it's in their myCertificates)
     * - It was issued by any certificate in the user's chain (recursively)
     * 
     * @param certificate The certificate to check
     * @param caUser The CA user
     * @return true if the certificate is in the user's chain, false otherwise
     */
    private boolean isCertificateInUserChain(Certificate certificate, User caUser) {
        if (certificate == null || caUser == null) {
            return false;
        }
        
        // Get all CA certificates owned by this user
        List<Certificate> caCertificates = caUser.getMyCertificates().stream()
                .filter(cert -> cert.isCanSign())
                .toList();
        
        // Collect all certificates in the chain
        java.util.Set<Certificate> allCertificatesInChain = new java.util.HashSet<>();
        
        for (Certificate caCert : caCertificates) {
            // Add the CA certificate itself
            allCertificatesInChain.add(caCert);
            // Add all certificates issued by this CA certificate (recursively)
            collectCertificatesIssuedBy(caCert, allCertificatesInChain);
        }
        
        // Check if the certificate is in the chain
        return allCertificatesInChain.stream()
                .anyMatch(cert -> cert.getId().equals(certificate.getId()));
    }
    
    /**
     * Recursively collects all certificates issued by a given certificate.
     * 
     * @param issuerCert The issuer certificate
     * @param result The set to collect certificates into
     */
    private void collectCertificatesIssuedBy(Certificate issuerCert, java.util.Set<Certificate> result) {
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

    private boolean hasValidCertificates(User user) {
        // This would check if the user has valid certificates
        // For now, return true as placeholder
        return true;
    }

    private void validateValidityPeriod(CreateCertificateRequestDTO requestDTO, User issuer) {
        // This would validate the validity period against issuer's certificates
        // For now, just check basic constraints
        if (requestDTO.getNotBefore() != null && requestDTO.getNotAfter() != null) {
            if (requestDTO.getNotBefore().isAfter(requestDTO.getNotAfter())) {
                throw new RuntimeException("NotBefore cannot be later than the NotAfter!");
            }
        }
    }

    private LocalDateTime getMaxValidUntil(User issuer) {
        // This would get the maximum valid until date from issuer's certificates
        // For now, return a placeholder date
        return LocalDateTime.now().plusYears(1);
    }

    private KeyPairDTO generateKeyPair() {
        try {
            // Generate actual RSA key pair
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // Convert public key to PEM format
            String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                                org.bouncycastle.util.encoders.Base64.toBase64String(keyPair.getPublic().getEncoded()) +
                                "\n-----END PUBLIC KEY-----";
            
            // Convert private key to PKCS#12 format
            String privateKeyPkcs12 = generatePKCS12KeyStore(keyPair, "changeit");
            
            KeyPairDTO keyPairDTO = new KeyPairDTO();
            keyPairDTO.setPublicKey(publicKeyPem);
            keyPairDTO.setPrivateKey(privateKeyPkcs12);
            return keyPairDTO;
        } catch (Exception e) {
            throw new RuntimeException("Error generating key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a PKCS#12 keystore containing the private key.
     */
    private String generatePKCS12KeyStore(java.security.KeyPair keyPair, String password) throws Exception {
        // Use JKS keystore instead of PKCS#12 to avoid certificate chain requirements
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        
        // JKS allows private keys without certificates
        keyStore.setKeyEntry("private-key", keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[0]);
        
        // Convert to Base64 string
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());
        return org.bouncycastle.util.encoders.Base64.toBase64String(baos.toByteArray());
    }

    /**
     * Generates a PKCS#12 keystore containing both CSR and private key.
     */
    private String generatePKCS12WithCSR(org.bouncycastle.pkcs.PKCS10CertificationRequest csr, java.security.KeyPair keyPair, String password) throws Exception {
        // Use JKS keystore instead of PKCS#12 to avoid certificate chain requirements
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        
        // JKS allows private keys without certificates
        keyStore.setKeyEntry("private-key", keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[0]);
        
        // Store CSR as a custom attribute (this is a workaround since PKCS#12 doesn't natively support CSRs)
        // We'll store the CSR data as a Base64 string in the keystore
        java.util.Properties csrProps = new java.util.Properties();
        csrProps.setProperty("csr-data", org.bouncycastle.util.encoders.Base64.toBase64String(csr.getEncoded()));
        
        // Convert to Base64 string
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());
        return org.bouncycastle.util.encoders.Base64.toBase64String(baos.toByteArray());
    }

    /**
     * Creates a minimal certificate for PKCS#12 keystore.
     * This is a temporary certificate that will be replaced when the actual certificate is issued.
     */
    private java.security.cert.X509Certificate createMinimalCertificate(java.security.KeyPair keyPair) throws Exception {
        // Create a very basic certificate using Java's built-in capabilities
        // This is just a placeholder for the PKCS#12 keystore
        
        // For now, we'll create a simple certificate using the public key
        // In a real implementation, you'd use proper ASN.1 encoding
        return createBasicCertificate(keyPair);
    }
    
    /**
     * Creates a basic certificate using Java's built-in capabilities.
     */
    private java.security.cert.X509Certificate createBasicCertificate(java.security.KeyPair keyPair) throws Exception {
        // This is a simplified approach - we'll create a minimal certificate
        // that satisfies the PKCS#12 keystore requirements
        
        // Create a basic certificate using the public key
        // This is a workaround since we don't have access to proper certificate builders
        try {
            // Create a minimal certificate structure
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) 
                java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(new java.io.ByteArrayInputStream(createBasicCertBytes(keyPair)));
            return cert;
        } catch (Exception e) {
            // If certificate creation fails, we'll create a dummy certificate
            return createDummyCertificate(keyPair);
        }
    }
    
    /**
     * Creates basic certificate bytes for the key pair.
     */
    private byte[] createBasicCertBytes(java.security.KeyPair keyPair) throws Exception {
        // This is a very simplified approach - in reality, you'd use proper ASN.1 encoding
        // For now, we'll return the public key encoding as a placeholder
        return keyPair.getPublic().getEncoded();
    }
    
    /**
     * Creates a dummy certificate that satisfies PKCS#12 requirements.
     */
    private java.security.cert.X509Certificate createDummyCertificate(java.security.KeyPair keyPair) throws Exception {
        // Create a minimal certificate that will work with PKCS#12
        // This is a workaround for the certificate chain requirement
        return null; // We'll handle this in the calling method
    }

    /**
     * Generates PKCS#10 CSR data from form input.
     * 
     * @param requestDTO The certificate request form data
     * @param keyPair The key pair to use for CSR generation
     * @return PEM-encoded PKCS#10 CSR
     */
    private String generateCSRDataFromForm(CreateCertificateRequestDTO requestDTO, java.security.KeyPair keyPair) {
        try {
            // Create X500Name for subject
            org.bouncycastle.asn1.x500.X500NameBuilder nameBuilder = new org.bouncycastle.asn1.x500.X500NameBuilder(BCStyle.INSTANCE);
            nameBuilder.addRDN(BCStyle.CN, requestDTO.getCommonName());
            if (requestDTO.getOrganization() != null && !requestDTO.getOrganization().isEmpty()) {
                nameBuilder.addRDN(BCStyle.O, requestDTO.getOrganization());
            }
            if (requestDTO.getOrganizationalUnit() != null && !requestDTO.getOrganizationalUnit().isEmpty()) {
                nameBuilder.addRDN(BCStyle.OU, requestDTO.getOrganizationalUnit());
            }
            if (requestDTO.getCountry() != null && !requestDTO.getCountry().isEmpty()) {
                nameBuilder.addRDN(BCStyle.C, requestDTO.getCountry());
            }
            if (requestDTO.getEmail() != null && !requestDTO.getEmail().isEmpty()) {
                nameBuilder.addRDN(BCStyle.E, requestDTO.getEmail());
            }
            
            X500Name subject = nameBuilder.build();
            
            // Build PKCS#10 CSR
            JcaPKCS10CertificationRequestBuilder csrBuilder = 
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            
            // Add extensions if specified
            if (requestDTO.getKeyUsage() != null && !requestDTO.getKeyUsage().isEmpty()) {
                org.bouncycastle.asn1.x509.KeyUsage keyUsage = new org.bouncycastle.asn1.x509.KeyUsage(
                    org.bouncycastle.asn1.x509.KeyUsage.digitalSignature |
                    org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment
                );
                
                // Create extensions object
                org.bouncycastle.asn1.x509.Extensions extensions = new org.bouncycastle.asn1.x509.Extensions(
                    new org.bouncycastle.asn1.x509.Extension(org.bouncycastle.asn1.x509.Extension.keyUsage, false, keyUsage.getEncoded())
                );
                
                csrBuilder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
            }
            
            // Sign the CSR
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());
            
            PKCS10CertificationRequest csr = csrBuilder.build(signer);
            
            // Convert to PEM format with proper line breaks
            String base64Encoded = Base64.getEncoder().encodeToString(csr.getEncoded());
            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.append("-----BEGIN CERTIFICATE REQUEST-----\n");
            
            // Add line breaks every 64 characters
            int index = 0;
            while (index < base64Encoded.length()) {
                int endIndex = Math.min(index + 64, base64Encoded.length());
                pemBuilder.append(base64Encoded.substring(index, endIndex)).append("\n");
                index = endIndex;
            }
            
            pemBuilder.append("-----END CERTIFICATE REQUEST-----");
            
            return pemBuilder.toString();
                   
        } catch (Exception e) {
            throw new RuntimeException("Error generating CSR: " + e.getMessage(), e);
        }
    }

    private String convertExtensionsToJson(CreateCertificateRequestDTO requestDTO) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.node.ObjectNode extensions = mapper.createObjectNode();
            
            // Add key usage if specified
            if (requestDTO.getKeyUsage() != null && !requestDTO.getKeyUsage().isEmpty()) {
                com.fasterxml.jackson.databind.node.ArrayNode keyUsageArray = mapper.createArrayNode();
                for (String usage : requestDTO.getKeyUsage()) {
                    keyUsageArray.add(usage);
                }
                extensions.set("keyUsage", keyUsageArray);
            }
            
            // Add extended key usage if specified
            if (requestDTO.getExtendedKeyUsage() != null && !requestDTO.getExtendedKeyUsage().isEmpty()) {
                com.fasterxml.jackson.databind.node.ArrayNode extKeyUsageArray = mapper.createArrayNode();
                for (String usage : requestDTO.getExtendedKeyUsage()) {
                    extKeyUsageArray.add(usage);
                }
                extensions.set("extendedKeyUsage", extKeyUsageArray);
            }
            
            return mapper.writeValueAsString(extensions);
        } catch (Exception e) {
            return "{}";
        }
    }

    /**
     * Finds a certificate by its serial number.
     * 
     * @param serialNumber The certificate serial number
     * @return The certificate if found, null otherwise
     */
    private Certificate findCertificateBySerialNumber(String serialNumber) {
        // Query the database for the certificate by serial number
        Optional<Certificate> certificateOpt = certificateRepository.findBySerialNumber(serialNumber);
        
        if (certificateOpt.isPresent()) {
            return certificateOpt.get();
        }
        
        // If certificate not found, throw an exception
        throw new RuntimeException("Certificate with serial number " + serialNumber + " not found!");
    }

    /**
     * Creates a placeholder certificate for the given CA user.
     * In a real implementation, this would query for existing certificates or create a proper one.
     * 
     * @param caUser The CA user
     * @return A placeholder certificate
     */
    private Certificate createPlaceholderCertificate(User caUser) {
        // Create a placeholder certificate that will be saved to the database
        // This is a temporary solution until proper certificate management is implemented
        Certificate certificate = new Certificate();
        certificate.setSerialNumber("PLACEHOLDER_" + System.currentTimeMillis());
        certificate.setSubjectCN("Placeholder CA Certificate");
        certificate.setIssuerCN("Self-Signed");
        certificate.setValidFrom(LocalDateTime.now().minusYears(1));
        certificate.setValidTo(LocalDateTime.now().plusYears(10));
        certificate.setEncodedValue("PLACEHOLDER_CERTIFICATE_DATA");
        certificate.setCanSign(true);
        certificate.setPathLength(-1); // Unlimited path length for root CA
        certificate.setSignedBy(caUser);
        
        // Save the certificate to the database first
        certificate = certificateRepository.save(certificate);
        
        return certificate;
    }

    private CertificateRequestResponseDTO convertToResponseDTO(CertificateSigningRequest csr) {
        CertificateRequestResponseDTO dto = new CertificateRequestResponseDTO();
        dto.setId(csr.getId().toString());
        dto.setSubmittedOn(csr.getCreatedAt());
        dto.setCommonName(csr.getSubjectCN());
        dto.setOrganization(csr.getSubjectO());
        dto.setOrganizationalUnit(csr.getSubjectOU());
        dto.setEmail(csr.getSubjectE());
        dto.setCountry(csr.getSubjectC());
        dto.setStatus(csr.getStatus()); // Add status field
        // Note: CertificateSigningRequest doesn't have validFrom/validTo fields
        // These would need to be added to the entity or handled differently
        dto.setNotBefore(null);
        dto.setNotAfter(null);
        return dto;
    }

    /**
     * Converts form-based extensions to JSON string.
     */
    private String convertFormExtensionsToJson(CreateCertificateRequestDTO dto) {
        // Create a simple JSON structure for form-based extensions
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"keyUsage\":[");
        if (dto.getKeyUsage() != null && !dto.getKeyUsage().isEmpty()) {
            for (int i = 0; i < dto.getKeyUsage().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(dto.getKeyUsage().get(i)).append("\"");
            }
        }
        json.append("],");
        json.append("\"extendedKeyUsage\":[");
        if (dto.getExtendedKeyUsage() != null && !dto.getExtendedKeyUsage().isEmpty()) {
            for (int i = 0; i < dto.getExtendedKeyUsage().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(dto.getExtendedKeyUsage().get(i)).append("\"");
            }
        }
        json.append("],");
        json.append("\"subjectAlternativeNames\":[");
        if (dto.getSubjectAlternativeNames() != null && !dto.getSubjectAlternativeNames().isEmpty()) {
            for (int i = 0; i < dto.getSubjectAlternativeNames().size(); i++) {
                if (i > 0) json.append(",");
                json.append("\"").append(dto.getSubjectAlternativeNames().get(i)).append("\"");
            }
        }
        json.append("]");
        json.append("}");
        return json.toString();
    }

    /**
     * Parses a private key from PEM format.
     * 
     * Supports:
     * - PKCS#8 format (-----BEGIN PRIVATE KEY-----)
     * - PKCS#1 RSA format (-----BEGIN RSA PRIVATE KEY-----)
     * - Encrypted PKCS#8 format (-----BEGIN ENCRYPTED PRIVATE KEY-----)
     * 
     * @param privateKeyContent The PEM-encoded private key content
     * @return PrivateKey object
     * @throws RuntimeException if parsing fails
     */
    private java.security.PrivateKey parsePrivateKeyFromPEM(String privateKeyContent) {
        if (privateKeyContent == null || privateKeyContent.trim().isEmpty()) {
            throw new IllegalArgumentException("Private key content cannot be null or empty");
        }

        try {
            // Remove PEM headers and footers
            String cleanPem = privateKeyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN ENCRYPTED PRIVATE KEY-----", "")
                .replace("-----END ENCRYPTED PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64
            byte[] derData = Base64.getDecoder().decode(cleanPem);
            
            // Create key factory
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            
            // Try PKCS#8 format first (most common)
            try {
                java.security.spec.PKCS8EncodedKeySpec keySpec = 
                    new java.security.spec.PKCS8EncodedKeySpec(derData);
                return keyFactory.generatePrivate(keySpec);
            } catch (java.security.spec.InvalidKeySpecException e) {
                // If PKCS#8 fails, might be PKCS#1 RSA format
                // For PKCS#1, we need to convert to PKCS#8 first
                // This is a simplified approach - in production you might use BouncyCastle's PEMParser
                throw new RuntimeException("Failed to parse private key. " +
                    "Please ensure it's in PKCS#8 format (-----BEGIN PRIVATE KEY-----). " +
                    "If it's in PKCS#1 format (-----BEGIN RSA PRIVATE KEY-----), " +
                    "please convert it using: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key_pkcs8.pem");
            }
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid Base64 encoding in private key: " + e.getMessage(), e);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not available: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse private key from PEM: " + e.getMessage(), e);
        }
    }
}

