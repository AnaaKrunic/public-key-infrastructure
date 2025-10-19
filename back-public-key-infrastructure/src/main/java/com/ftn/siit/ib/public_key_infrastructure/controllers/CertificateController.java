package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.CertificateService;
import com.ftn.siit.ib.public_key_infrastructure.services.FileDownloadService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/certificates")
@CrossOrigin(origins = "*")
public class CertificateController {

    private final CertificateService certificateService;
    private final FileDownloadService fileDownloadService;
    private final UserRepository userRepository;

    public CertificateController(CertificateService certificateService, FileDownloadService fileDownloadService, UserRepository userRepository) {
        this.certificateService = certificateService;
        this.fileDownloadService = fileDownloadService;
        this.userRepository = userRepository;
    }

    /**
     * Issues a certificate on behalf of the current CA or admin.
     * Requires Admin or CaUser role.
     */
    @PostMapping("/issue")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> issueCertificate(@RequestBody IssueCertificateRequestDTO dto) {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            String role = getCurrentUserRole(authentication);
            
            boolean isAdmin = "ADMIN".equals(role);
            certificateService.createCertificate(dto, isAdmin, userId, userId);
            
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error issuing certificate: " + e.getMessage());
        }
    }

    /**
     * Gets all certificates with pagination support.
     * Access depends on user role.
     */
    @GetMapping("/get-all")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<?> getAllCertificates() {
        try {
            var certificates = certificateService.getAllCertificates();
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving certificates: " + e.getMessage());
        }
    }

    /**
     * Gets all valid signing certificates.
     * Access depends on user role.
     */
    @GetMapping("/get-all-valid-signing")
    public ResponseEntity<?> getAllValidSigningCertificates() {
        try {
            var certificates = certificateService.getAllValidSigningCertificates();
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving valid signing certificates: " + e.getMessage());
        }
    }

    /**
     * Gets valid CA certificates from the current CA user's chain that can be used for signing.
     * Requires CA_USER role.
     */
    @GetMapping("/get-organization-signing-certificates")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> getOrganizationSigningCertificates() {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            var certificates = certificateService.getMyValidSigningCertificates(userId);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving signing certificates: " + e.getMessage());
        }
    }

    /**
     * Adds a certificate to a CA user.
     * Requires Admin access.
     */
    @PutMapping("/add-certificate-to-ca-user")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> addCertificateToCaUser(@RequestBody AddCertificateToCaUserRequestDTO dto) {
        try {
            certificateService.addCertificateToCaUser(dto);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error adding certificate to CA user: " + e.getMessage());
        }
    }

    /**
     * Lists valid signing certificates not yet assigned to the specified CA user.
     * Requires Admin role.
     */
    @GetMapping("/get-signing-ca-doesnt-have/{caUserId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getSigningCaDoesntHave(@PathVariable String caUserId) {
        try {
            var certificates = certificateService.getValidSigningCertificatesCaUserDoesntHave(caUserId);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving certificates: " + e.getMessage());
        }
    }

    /**
     * Retrieves every certificate belonging to the signed-in user.
     * Requires authentication.
     */
    @GetMapping("/get-my-certificates")
    public ResponseEntity<?> getMyCertificates() {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            var certificates = certificateService.getMyCertificates(userId);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving my certificates: " + e.getMessage());
        }
    }

    /**
     * Retrieves only the currently valid certificates for the signed-in user.
     * Requires authentication.
     */
    @GetMapping("/get-my-valid-certificates")
    public ResponseEntity<?> getMyValidCertificates() {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            var certificates = certificateService.getMyValidCertificates(userId);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving my valid certificates: " + e.getMessage());
        }
    }

    /**
     * Returns certificates issued by the current CA user.
     * Requires CaUser role.
     */
    @GetMapping("/get-certificates-signed-by-me")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> getCertificatesSignedByMe() {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            var certificates = certificateService.getCertificatesSignedByMe(userId);
            return ResponseEntity.ok(certificates);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error retrieving certificates signed by me: " + e.getMessage());
        }
    }

    /**
     * Provides a PKCS#12 archive (.pfx) for a certificate the caller is authorized to access.
     * Requires Admin, CaUser, or EeUser role.
     */
    @PostMapping("/download")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'EE_USER')")
    public ResponseEntity<?> downloadCertificate(@RequestBody DownloadCertificateRequestDTO dto) {
        try {
            // Validate request
            if (dto == null) {
                return ResponseEntity.badRequest()
                        .body("Request body cannot be null");
            }
            if (dto.getCertificateSerialNumber() == null || dto.getCertificateSerialNumber().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body("Certificate serial number is required");
            }
            if (dto.getPassword() == null || dto.getPassword().length() < 6) {
                return ResponseEntity.badRequest()
                        .body("Password must be at least 6 characters long");
            }
            
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userEmail = authentication.getName();
            
            // Look up the actual user by email to get their ID
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            Long userId = user.getId();
            Role role = user.getRole();
            
            // Generate PKCS#12 file
            byte[] pfxBytes = certificateService.getCertificateWithPasswordAsPkcs12(dto, userId, role);
            
            // Create proper headers using FileDownloadService
            HttpHeaders headers = fileDownloadService.createDownloadHeaders(
                "application/x-pkcs12",
                "certificate_" + dto.getCertificateSerialNumber() + ".pfx",
                pfxBytes.length
            );
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(pfxBytes);
                    
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body("Invalid request: " + e.getMessage());
        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            } else if (e.getMessage().contains("Access denied")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Access denied: " + e.getMessage());
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error downloading certificate: " + e.getMessage());
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Unexpected error downloading certificate: " + e.getMessage());
        }
    }

    /**
     * Downloads a certificate in various formats (PEM, DER, PKCS#12).
     * Requires Admin, CaUser, or EeUser role.
     */
    @GetMapping("/download/{serialNumber}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'EE_USER')")
    public ResponseEntity<?> downloadCertificateInFormat(
            @PathVariable String serialNumber,
            @RequestParam(defaultValue = "PEM") String format,
            @RequestParam(required = false) String password) {
        try {
            // Validate parameters
            if (serialNumber == null || serialNumber.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body("Certificate serial number is required");
            }
            
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long userId = Long.parseLong(getCurrentUserId(authentication));
            Role role = getCurrentUserRoleEnum(authentication);
            
            // Find the certificate
            Optional<Certificate> certificateOpt = certificateService.findBySerialNumber(serialNumber);
            if (!certificateOpt.isPresent()) {
                return ResponseEntity.notFound().build();
            }
            Certificate certificate = certificateOpt.get();
            
            // Check authorization
            User user = certificateService.getUserRepository().findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));
            
            // Check authorization - Admin has access to all certificates
            if (user.getRole() != Role.ADMIN) {
                // CA users can access certificates from their organization (including those that signed their CA)
                if (user.getRole() == Role.CA_USER) {
                    // Check if certificate belongs to the CA user's organization
                    boolean hasAccess = certificate.getSigningOrganization() != null && 
                                      certificate.getSigningOrganization().equals(user.getOrganization());
                    
                    // Also check if certificate was signed by a CA user from the same organization
                    if (!hasAccess && certificate.getSignedBy() != null && 
                        certificate.getSignedBy().getRole() == Role.CA_USER && 
                        certificate.getSignedBy().getOrganization().equals(user.getOrganization())) {
                        hasAccess = true;
                    }
                    
                    if (!hasAccess) {
                        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body("Access denied to certificate");
                    }
                }
                
                // Users can access their own certificates
                if (user.getRole() == Role.EE_USER && !user.getMyCertificates().contains(certificate)) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body("Access denied to certificate");
                }
            }
            
            // Generate file based on format
            byte[] fileData;
            String contentType;
            String filename;
            
            switch (format.toUpperCase()) {
                case "PEM":
                    fileData = certificate.getCertificateData().getBytes();
                    contentType = "application/x-pem-file";
                    filename = "certificate_" + serialNumber + ".pem";
                    break;
                case "DER":
                    // Convert PEM to DER
                    String cleanPem = certificate.getCertificateData()
                            .replace("-----BEGIN CERTIFICATE-----", "")
                            .replace("-----END CERTIFICATE-----", "")
                            .replaceAll("\\s", "");
                    fileData = java.util.Base64.getDecoder().decode(cleanPem);
                    contentType = "application/x-x509-ca-cert";
                    filename = "certificate_" + serialNumber + ".der";
                    break;
                case "PKCS12":
                case "PFX":
                    if (password == null || password.length() < 6) {
                        return ResponseEntity.badRequest()
                                .body("Password is required for PKCS#12 format and must be at least 6 characters");
                    }
                    DownloadCertificateRequestDTO request = new DownloadCertificateRequestDTO();
                    request.setCertificateSerialNumber(serialNumber);
                    request.setPassword(password);
                    fileData = certificateService.getCertificateWithPasswordAsPkcs12(request, userId, role);
                    contentType = "application/x-pkcs12";
                    filename = "certificate_" + serialNumber + ".pfx";
                    break;
                default:
                    return ResponseEntity.badRequest()
                            .body("Unsupported format. Supported formats: PEM, DER, PKCS12, PFX");
            }
            
            // Set proper headers for file download
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(contentType));
            headers.setContentDispositionFormData("attachment", filename);
            headers.setContentLength(fileData.length);
            headers.setCacheControl("no-cache, no-store, must-revalidate");
            headers.setPragma("no-cache");
            headers.setExpires(0);
            
            return ResponseEntity.ok()
                    .headers(headers)
                    .body(fileData);
                    
        } catch (RuntimeException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            } else if (e.getMessage().contains("Access denied")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Access denied: " + e.getMessage());
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Error downloading certificate: " + e.getMessage());
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Unexpected error downloading certificate: " + e.getMessage());
        }
    }

    /**
     * Creates a root CA certificate (self-signed).
     * Requires Admin role.
     */
    @PostMapping("/root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createRootCertificate(@RequestBody CreateRootCertificateDTO dto) {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            // Fetch the User object from database
            User admin = certificateService.getUserRepository().findById(Long.parseLong(userId))
                    .orElseThrow(() -> new RuntimeException("User not found"));
            
            var certificate = certificateService.createRootCertificate(dto, admin);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error creating root certificate: " + e.getMessage());
        }
    }

    /**
     * Creates an intermediate CA certificate.
     * Requires Admin or CA_USER role.
     */
    @PostMapping("/intermediate")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> createIntermediateCertificate(@RequestBody CreateIntermediateCertificateDTO dto) {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            // Fetch the User object from database
            User user = certificateService.getUserRepository().findById(Long.parseLong(userId))
                    .orElseThrow(() -> new RuntimeException("User not found"));
            
            var certificate = certificateService.createIntermediateCertificate(dto, user);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error creating intermediate certificate: " + e.getMessage());
        }
    }

    /**
     * Creates an end entity certificate.
     * Requires Admin or CA_USER role.
     */
    @PostMapping("/end-entity")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")
    public ResponseEntity<?> createEndEntityCertificate(@RequestBody CreateEndEntityCertificateDTO dto) {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String userId = getCurrentUserId(authentication);
            
            // Fetch the User object from database
            User user = certificateService.getUserRepository().findById(Long.parseLong(userId))
                    .orElseThrow(() -> new RuntimeException("User not found"));
            
            var certificate = certificateService.createEndEntityCertificate(dto, user);
            return ResponseEntity.ok(certificate);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error creating end entity certificate: " + e.getMessage());
        }
    }

    /**
     * Helper method to get current user ID from authentication context.
     */
    private String getCurrentUserId(Authentication authentication) {
        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getId().toString();
    }

    /**
     * Helper method to get current user role from authentication context.
     */
    private String getCurrentUserRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(authority -> {
                    String authorityName = authority.getAuthority();
                    if (authorityName.startsWith("ROLE_")) {
                        authorityName = authorityName.substring(5); // Remove "ROLE_" prefix
                    }
                    return authorityName;
                })
                .findFirst()
                .orElse("EE_USER");
    }

    /**
     * Helper method to get current user role as enum from authentication context.
     */
    private Role getCurrentUserRoleEnum(Authentication authentication) {
        String roleName = getCurrentUserRole(authentication);
        return Role.valueOf(roleName);
    }
}
