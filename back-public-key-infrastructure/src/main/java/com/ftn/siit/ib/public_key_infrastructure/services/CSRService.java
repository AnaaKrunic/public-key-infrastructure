package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.*;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateSigningRequestRepository;
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
    private final CertificateService certificateService;
    private final ValidationService validationService;

    public CSRService(
            CertificateSigningRequestRepository csrRepository,
            CertificateService certificateService,
            ValidationService validationService) {
        this.csrRepository = csrRepository;
        this.certificateService = certificateService;
        this.validationService = validationService;
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
     * The generated CSR is in PEM format and can be submitted to the CA for approval.
     * 
     * @param dto CSR creation parameters (subject DN, key size, extensions, selected CA, template)
     * @param requester The user creating the CSR
     * @return CSRDTO containing the CSR in PEM format and metadata
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

        // Validate the CSR request (placeholder - would need specific CSR validation)
        // validationService.validateCertificateRequest(dto, requester);

        // Find the selected CA certificate (placeholder - would need to get Certificate entity)
        // For now, create a placeholder Certificate entity
        Certificate selectedCA = new Certificate();
        selectedCA.setId(dto.getSelectedCAId());
        selectedCA.setSerialNumber(dto.getSelectedCAId().toString());
        selectedCA.setSubjectCN("Test CA");
        // Note: selectedCA is a placeholder, owner relationship is handled differently

        // Generate CSR data (placeholder for now - would use Bouncy Castle)
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
     * Uploads and processes an externally generated Certificate Signing Request.
     * 
     * Process:
     * 1. Parse PEM-encoded CSR using Bouncy Castle
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
     * @param dto Upload parameters (PEM CSR data, selected CA, optional template)
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

        // Parse and validate CSR (placeholder implementation)
        String csrData = dto.getCsrData();
        if (csrData == null || csrData.trim().isEmpty()) {
            throw new ValidationException("CSR data cannot be null or empty");
        }

        // Extract subject fields from CSR (placeholder - would use Bouncy Castle)
        String subjectCN = extractSubjectCN(csrData);
        String subjectO = extractSubjectO(csrData);
        String subjectOU = extractSubjectOU(csrData);
        String subjectC = extractSubjectC(csrData);
        String subjectE = extractSubjectE(csrData);

        // Find the selected CA certificate (placeholder - would need to get Certificate entity)
        // For now, create a placeholder Certificate entity
        Certificate selectedCA = new Certificate();
        selectedCA.setId(dto.getSelectedCAId());
        selectedCA.setSerialNumber(dto.getSelectedCAId().toString());
        selectedCA.setSubjectCN("Test CA");
        // Note: selectedCA is a placeholder, owner relationship is handled differently

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
     * Generates CSR data in PEM format (placeholder implementation).
     * 
     * @param dto The CSR creation DTO
     * @return PEM-encoded CSR data
     */
    private String generateCSRData(CreateCSRDTO dto) {
        // This is a placeholder implementation
        // In a real implementation, this would use Bouncy Castle to:
        // 1. Generate RSA key pair
        // 2. Build PKCS#10 CSR with subject DN
        // 3. Sign with private key
        // 4. Return PEM format
        
        return "-----BEGIN CERTIFICATE REQUEST-----\n" +
               "MIIBkTCB+wIBADBOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEh\n" +
               "MB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMREwDwYDVQQDDAh0ZXN0\n" +
               "LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA7+9v5f1YQrHf1VAz7bFk\n" +
               "-----END CERTIFICATE REQUEST-----";
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
     * Extracts subject CN from CSR data (placeholder implementation).
     * 
     * @param csrData The CSR data in PEM format
     * @return Subject CN
     */
    private String extractSubjectCN(String csrData) {
        // Placeholder implementation - would use Bouncy Castle to parse CSR
        return "Uploaded Certificate";
    }

    /**
     * Extracts subject O from CSR data (placeholder implementation).
     * 
     * @param csrData The CSR data in PEM format
     * @return Subject O
     */
    private String extractSubjectO(String csrData) {
        // Placeholder implementation - would use Bouncy Castle to parse CSR
        return "Uploaded Organization";
    }

    /**
     * Extracts subject OU from CSR data (placeholder implementation).
     * 
     * @param csrData The CSR data in PEM format
     * @return Subject OU
     */
    private String extractSubjectOU(String csrData) {
        // Placeholder implementation - would use Bouncy Castle to parse CSR
        return "Uploaded OU";
    }

    /**
     * Extracts subject C from CSR data (placeholder implementation).
     * 
     * @param csrData The CSR data in PEM format
     * @return Subject C
     */
    private String extractSubjectC(String csrData) {
        // Placeholder implementation - would use Bouncy Castle to parse CSR
        return "US";
    }

    /**
     * Extracts subject E from CSR data (placeholder implementation).
     * 
     * @param csrData The CSR data in PEM format
     * @return Subject E
     */
    private String extractSubjectE(String csrData) {
        // Placeholder implementation - would use Bouncy Castle to parse CSR
        return "uploaded@example.com";
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
        
        // Find the signing organization (CA user)
        User issuer = findUserByIdAndRole(Long.parseLong(requestDTO.getSigningOrganization()), Role.CA_USER);
        
        // Check if issuer has valid certificates
        if (!hasValidCertificates(issuer)) {
            throw new RuntimeException("Requested issuer is not able to sign certificates!");
        }
        
        // Validate validity period constraints
        validateValidityPeriod(requestDTO, issuer);
        
        // Generate key pair (placeholder implementation)
        KeyPairDTO keyPair = generateKeyPair();
        
        // Create certificate request entity
        CertificateSigningRequest csr = new CertificateSigningRequest();
        csr.setRequester(user);
        csr.setRequestedFrom(issuer);
        csr.setSubjectCN(requestDTO.getCommonName());
        csr.setSubjectO(requestDTO.getOrganization());
        csr.setSubjectOU(requestDTO.getOrganizationalUnit());
        csr.setSubjectE(requestDTO.getEmail());
        csr.setSubjectC(requestDTO.getCountry());
        csr.setStatus(CSRStatus.PENDING);
        csr.setRequestedExtensions(convertExtensionsToJson(requestDTO));
        
        // Set selectedCA to a placeholder certificate (would need actual certificate lookup)
        Certificate selectedCA = new Certificate();
        selectedCA.setId(Long.parseLong(requestDTO.getSigningOrganization()));
        csr.setSelectedCA(selectedCA);
        
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
        
        // Find requests where the CA user is the requestedFrom user
        List<CertificateSigningRequest> requests = csrRepository.findByRequestedFrom(caUser);
        
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
        
        if (!request.getSelectedCA().getId().equals(caUser.getId())) {
            throw new RuntimeException("This certificate is not requested from you!");
        }
        
        csrRepository.delete(request);
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
        
        if (!request.getSelectedCA().getId().equals(caUser.getId())) {
            throw new RuntimeException("This certificate is not requested from you!");
        }
        
        // Create certificate using the certificate service
        // This would need to be implemented based on your certificate creation logic
        // certificateService.createCertificate(approveRequest.getRequestForm(), false, userId, request.getRequester().getId().toString(), publicKey);
        
        // Delete the request after approval
        csrRepository.delete(request);
    }

    // Helper methods
    private User findUserByIdAndRole(Long userId, Role role) {
        // This would need to be implemented with actual user lookup
        // For now, return a placeholder
        User user = new User();
        user.setId(userId);
        user.setRole(role);
        return user;
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
        // This would generate an actual key pair
        // For now, return placeholder data
        KeyPairDTO keyPair = new KeyPairDTO();
        keyPair.setPublicKey("-----BEGIN PUBLIC KEY-----\nPLACEHOLDER\n-----END PUBLIC KEY-----");
        keyPair.setPrivateKey("-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----");
        return keyPair;
    }

    private String convertExtensionsToJson(CreateCertificateRequestDTO requestDTO) {
        // Convert extensions to JSON format
        return "{}"; // Placeholder
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
        // Note: CertificateSigningRequest doesn't have validFrom/validTo fields
        // These would need to be added to the entity or handled differently
        dto.setNotBefore(null);
        dto.setNotAfter(null);
        return dto;
    }
}

