package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.RevokeCertificateRequestDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.services.CRLService;
import com.ftn.siit.ib.public_key_infrastructure.services.FileDownloadService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/crl")
@CrossOrigin(origins = "*")
public class CRLController {

    private final CRLService crlService;
    private final FileDownloadService fileDownloadService;

    public CRLController(CRLService crlService, FileDownloadService fileDownloadService) {
        this.crlService = crlService;
        this.fileDownloadService = fileDownloadService;
    }

    /**
     * Returns the set of recorded certificate revocations.
     * Anonymous access allowed.
     */
    @GetMapping("/web")
    public ResponseEntity<?> getRevocations() {
        try {
            var revokedCertificates = crlService.getAllRevokedCertificates();
            return ResponseEntity.ok(revokedCertificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving revoked certificates: " + e.getMessage());
        }
    }

    /**
     * Adds a certificate to the revocation list.
     * Requires authentication.
     */
    @PostMapping("/revoke")
    public ResponseEntity<?> revokeCertificate(@RequestBody RevokeCertificateRequestDTO dto) {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            // Get user role from authentication
            Role requesterRole = authentication.getAuthorities().stream()
                    .map(authority -> {
                        String authorityName = authority.getAuthority();
                        if (authorityName.startsWith("ROLE_")) {
                            authorityName = authorityName.substring(5); // Remove "ROLE_" prefix
                        }
                        return Role.valueOf(authorityName);
                    })
                    .findFirst()
                    .orElse(Role.EE_USER);

            // For now, we'll use a placeholder user ID since we don't have user lookup here
            // In a real implementation, you'd look up the user by email
            Long requesterId = 1L; // This should be replaced with actual user lookup

            crlService.revokeCertificate(dto, requesterId, requesterRole);
            
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error revoking certificate: " + e.getMessage());
        }
    }

    /**
     * Downloads the current certificate revocation list (CRL) file.
     * Anonymous access allowed.
     */
    @GetMapping("/")
    public ResponseEntity<?> downloadCRL() {
        try {
            byte[] crlData = crlService.getRevocationFile();
            
            if (crlData == null || crlData.length == 0) {
                return ResponseEntity.noContent().build();
            }
            
            // Create proper headers using FileDownloadService
            HttpHeaders headers = fileDownloadService.createDownloadHeaders(
                "application/pkix-crl",
                fileDownloadService.generateCrlFilename(),
                crlData.length
            );
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(crlData);
                    
        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error generating CRL: " + e.getMessage());
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Unexpected error generating CRL: " + e.getMessage());
        }
    }
}
