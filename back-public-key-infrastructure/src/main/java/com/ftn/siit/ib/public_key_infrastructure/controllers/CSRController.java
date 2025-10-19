package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.services.CSRService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/csr")
@CrossOrigin(origins = "*")
public class CSRController {

    private final CSRService csrService;

    public CSRController(CSRService csrService) {
        this.csrService = csrService;
    }

    /**
     * Generates a new certificate signing request (CSR) and key pair from supplied subject details.
     * Requires EeUser role.
     */
    @PostMapping("/form")
    @PreAuthorize("hasRole('EE_USER')")
    public ResponseEntity<?> generateCSRFromForm(@RequestBody CreateCertificateRequestDTO dto) {
        try {
            // Get current user ID from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long userId = getCurrentUserId(authentication);
            
            CSRDTO csr = csrService.createFormBasedCSR(dto, userId);
            return ResponseEntity.ok(csr);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error creating certificate request: " + e.getMessage());
        }
    }

    /**
     * Uploads an externally generated CSR and private key for processing.
     * Requires EeUser role.
     */
    @PostMapping("/upload")
    @PreAuthorize("hasRole('EE_USER')")
    public ResponseEntity<?> uploadCSR(
            @RequestParam("csrFile") MultipartFile csrFile,
            @RequestParam("privateKeyFile") MultipartFile privateKeyFile,
            @RequestParam("signingCertificate") String signingCertificate,
            @RequestParam(value = "notAfter", required = false) String notAfterStr) {
        try {
            // Get current user ID from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long userId = getCurrentUserId(authentication);
            
            // Validate required fields
            if (csrFile == null || csrFile.isEmpty()) {
                return ResponseEntity.badRequest().body("Missing CSR file!");
            }
            
            if (privateKeyFile == null || privateKeyFile.isEmpty()) {
                return ResponseEntity.badRequest().body("Missing private key file!");
            }
            
            if (signingCertificate == null || signingCertificate.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Missing signing certificate!");
            }
            
            // Read file contents
            String csrContent = new String(csrFile.getBytes());
            String privateKeyContent = new String(privateKeyFile.getBytes());
            
            // Parse notAfter date if provided
            LocalDateTime notAfter = null;
            if (notAfterStr != null && !notAfterStr.trim().isEmpty()) {
                notAfter = LocalDateTime.parse(notAfterStr);
            }
            
            csrService.uploadCSRWithPrivateKey(signingCertificate, csrContent, privateKeyContent, notAfter, userId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error uploading CSR: " + e.getMessage());
        }
    }

    /**
     * Lists certificate requests awaiting action for the signed-in CA user.
     * Requires CaUser role.
     */
    @GetMapping("/")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> listPendingRequests() {
        try {
            // Get current user ID from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long userId = getCurrentUserId(authentication);
            
            var requests = csrService.getCertificateRequests(userId);
            return ResponseEntity.ok(requests);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving certificate requests: " + e.getMessage());
        }
    }

    /**
     * Rejects a pending certificate request.
     * Requires CaUser role.
     */
    @PostMapping("/reject")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> rejectRequest(@RequestBody String requestId) {
        try {
            // Get current user ID from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long userId = getCurrentUserId(authentication);
            
            csrService.deleteCertificateRequest(userId, requestId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error rejecting request: " + e.getMessage());
        }
    }

    /**
     * Approves and fulfills a certificate request.
     * Requires CaUser role.
     */
    @PostMapping("/approve")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> approveRequest(@RequestBody ApproveCertificateRequestDTO dto) {
        try {
            // Get current user ID from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long userId = getCurrentUserId(authentication);
            
            csrService.approveCertificateRequest(userId, dto);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error approving request: " + e.getMessage());
        }
    }

    /**
     * Helper method to get current user ID from authentication context.
     * This is a placeholder implementation - in a real system, you'd look up the user by email.
     */
    private Long getCurrentUserId(Authentication authentication) {
        // This is a placeholder - in a real implementation, you'd look up the user by email
        // and return their actual ID
        return 1L;
    }
}
