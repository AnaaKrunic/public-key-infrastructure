package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateEndEntityCertificateDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateTemplate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.*;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.CertificateSignerService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * ValidationService provides comprehensive validation for certificates, certificate chains,
 * and template constraints in the PKI system.
 * 
 * This service is foundational and used by other services to ensure data integrity,
 * security compliance, and business rule enforcement.
 */
@Service
public class ValidationService {

    private final CertificateSignerService certificateSignerService;

    public ValidationService(CertificateSignerService certificateSignerService) {
        this.certificateSignerService = certificateSignerService;
    }

    /**
     * Validates that a certificate is a valid CA certificate that can issue other certificates.
     * 
     * Validation checks:
     * - Certificate type must be ROOT or INTERMEDIATE
     * - Certificate status must be VALID (not REVOKED)
     * - Certificate must be within its validity period (notBefore <= now <= notAfter)
     * - Certificate must have keyCertSign key usage
     * 
     * @param issuer The certificate to validate as a CA
     * @throws IllegalArgumentException if issuer is null
     * @throws InvalidCertificateException if the certificate is not a valid CA certificate
     */
    public void validateIssuerCertificate(Certificate issuer) {
        if (issuer == null) {
            throw new IllegalArgumentException("Issuer certificate cannot be null");
        }

        // Check certificate type
        if (issuer.getCertificateType() != CertificateType.ROOT && issuer.getCertificateType() != CertificateType.INTERMEDIATE) {
            throw new InvalidCertificateException("Certificate must be ROOT or INTERMEDIATE type to be a valid CA");
        }

        // Check certificate status
        if (issuer.getStatus() != CertificateStatus.ACTIVE) {
            throw new InvalidCertificateException("Certificate must be VALID to be used as a CA");
        }

        // Check validity period
        LocalDateTime now = LocalDateTime.now();
        if (now.isBefore(issuer.getValidFrom()) || now.isAfter(issuer.getValidTo())) {
            throw new InvalidCertificateException("Certificate is not within its validity period");
        }

        // Check key usage contains keyCertSign
        if (issuer.getKeyUsage() == null || !issuer.getKeyUsage().contains("keyCertSign")) {
            throw new InvalidCertificateException("Certificate must have keyCertSign key usage to be a valid CA");
        }
    }

    /**
     * Validates the entire certificate chain from a given certificate to the root CA.
     * 
     * This method:
     * - Builds the chain by following issuerCertificate references
     * - Validates each certificate in the chain using validateIssuerCertificate
     * - Verifies cryptographic signatures using CertificateSignerService
     * - Checks path length constraints for intermediate CAs
     * - Ensures the chain terminates at a self-signed root certificate
     * 
     * @param certificate The certificate whose chain should be validated
     * @return List of certificates in the chain, ordered from end-entity to root
     * @throws IllegalArgumentException if certificate is null
     * @throws InvalidCertificateChainException if the chain is broken, invalid, or doesn't terminate at a root
     */
    public List<Certificate> validateCertificateChain(Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        List<Certificate> chain = new ArrayList<>();
        Certificate current = certificate;
        int pathLength = 0;
        final int MAX_PATH_LENGTH = 10; // Prevent infinite loops

        while (current != null && pathLength < MAX_PATH_LENGTH) {
            chain.add(current);
            
            // Validate current certificate
            if (current.getCertificateType() == CertificateType.ROOT || 
                current.getCertificateType() == CertificateType.INTERMEDIATE) {
                validateIssuerCertificate(current);
            }

            // Check if we've reached the root (self-signed)
            if (current.getCertificateType() == CertificateType.ROOT) {
                // Verify it's self-signed by checking if issuer equals subject
                if (current.getIssuerDN() != null && current.getSubjectDN() != null &&
                    current.getIssuerDN().equals(current.getSubjectDN())) {
                    break; // Valid root certificate
                } else {
                    throw new InvalidCertificateChainException("Root certificate is not self-signed");
                }
            }

            // Move to issuer certificate
            current = current.getIssuerCertificate();
            pathLength++;
        }

        if (pathLength >= MAX_PATH_LENGTH) {
            throw new InvalidCertificateChainException("Certificate chain too long or contains circular references");
        }

        if (chain.isEmpty() || chain.get(chain.size() - 1).getCertificateType() != CertificateType.ROOT) {
            throw new InvalidCertificateChainException("Certificate chain does not terminate at a root certificate");
        }

        return chain;
    }

    /**
     * Validates that a certificate creation request complies with the constraints
     * defined in a certificate template.
     * 
     * Validation checks:
     * - Common Name (CN) matches the template's commonNamePattern regex
     * - Subject Alternative Names (SANs) match the template's sanPattern regex
     * - Requested validity period (validityDays) does not exceed template's ttlDays
     * - Issuer certificate matches the template's issuerCertificate
     * - All required fields are present
     * 
     * @param template The certificate template defining the constraints
     * @param request The certificate creation request to validate
     * @throws IllegalArgumentException if template or request is null
     * @throws TemplateConstraintViolationException if any constraint is violated, with specific details
     */
    public void validateTemplateConstraints(CertificateTemplate template, CreateEndEntityCertificateDTO request) {
        if (template == null) {
            throw new IllegalArgumentException("Template cannot be null");
        }
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }

        // Validate Common Name pattern
        if (template.getCommonNamePattern() != null && !template.getCommonNamePattern().trim().isEmpty()) {
            if (request.getSubjectCN() == null || !Pattern.matches(template.getCommonNamePattern(), request.getSubjectCN())) {
                throw new TemplateConstraintViolationException(
                    "Subject CN '" + request.getSubjectCN() + "' does not match template pattern '" + template.getCommonNamePattern() + "'");
            }
        }

        // Validate Subject Alternative Names pattern
        if (template.getSanPattern() != null && !template.getSanPattern().trim().isEmpty()) {
            if (request.getSubjectAlternativeNames() != null) {
                for (String san : request.getSubjectAlternativeNames()) {
                    if (!Pattern.matches(template.getSanPattern(), san)) {
                        throw new TemplateConstraintViolationException(
                            "Subject Alternative Name '" + san + "' does not match template pattern '" + template.getSanPattern() + "'");
                    }
                }
            }
        }

        // Validate validity days
        if (template.getTtlDays() != null && request.getValidityDays() != null) {
            if (request.getValidityDays() > template.getTtlDays()) {
                throw new TemplateConstraintViolationException(
                    "Requested validity days (" + request.getValidityDays() + ") exceeds template limit (" + template.getTtlDays() + ")");
            }
        }

        // Validate issuer certificate matches
        if (template.getIssuerCertificate() != null && request.getIssuerCertificateId() != null) {
            if (!template.getIssuerCertificate().getId().equals(request.getIssuerCertificateId())) {
                throw new TemplateConstraintViolationException(
                    "Requested issuer certificate does not match template issuer certificate");
            }
        }
    }

    /**
     * Validates a certificate creation request for business rules and security constraints.
     * 
     * Validation checks:
     * - Issuer certificate exists and is a valid CA
     * - Requester has permission to use the specified issuer certificate
     *   (CA_USER can only use their own CA certificates)
     * - Distinguished Name fields are valid:
     *   * CN is required and not empty
     *   * Country code (C) must be 2-letter uppercase ISO 3166-1 code
     *   * Email (E) must be valid format
     * - Key usage does not contain CA-only usages (keyCertSign, cRLSign)
     * - Requested validity period does not exceed issuer's remaining validity
     * - If template is specified, it exists and is owned by the CA user
     * 
     * @param request The certificate creation request to validate
     * @param requester The user making the request
     * @throws IllegalArgumentException if request or requester is null
     * @throws ValidationException if any validation rule is violated, with field-specific error details
     */
    public void validateCertificateRequest(CreateEndEntityCertificateDTO request, User requester) {
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Validate Distinguished Name fields
        validateDistinguishedName(
            request.getSubjectCN(),
            request.getSubjectO(),
            request.getSubjectOU(),
            request.getSubjectL(),
            request.getSubjectST(),
            request.getSubjectC(),
            request.getSubjectE()
        );

        // Validate key usage for end-entity certificates
        if (request.getKeyUsage() != null) {
            validateKeyUsage(request.getKeyUsage(), false); // false = not a CA certificate
        }

        // Validate email format if provided
        if (request.getSubjectE() != null && !request.getSubjectE().trim().isEmpty()) {
            String emailPattern = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
            if (!Pattern.matches(emailPattern, request.getSubjectE())) {
                throw new ValidationException("Invalid email format: " + request.getSubjectE());
            }
        }

        // Validate country code if provided
        if (request.getSubjectC() != null && !request.getSubjectC().trim().isEmpty()) {
            if (!Pattern.matches("^[A-Z]{2}$", request.getSubjectC())) {
                throw new ValidationException("Country code must be a 2-letter ISO code: " + request.getSubjectC());
            }
        }

        // Validate required fields
        if (request.getSubjectCN() == null || request.getSubjectCN().trim().isEmpty()) {
            throw new ValidationException("Subject CN is required");
        }

        if (request.getValidityDays() == null || request.getValidityDays() <= 0) {
            throw new ValidationException("Validity days must be a positive number");
        }

        if (request.getKeySize() == null || request.getKeySize() < 2048) {
            throw new ValidationException("Key size must be at least 2048 bits");
        }
    }

    /**
     * Validates that a user has permission to revoke a certificate.
     * 
     * Permission rules:
     * - Certificate owner can revoke their own certificates
     * - CA user who issued the certificate can revoke it
     * - ADMIN users can revoke any certificate
     * - Certificate must not already be revoked
     * 
     * @param certificate The certificate to be revoked
     * @param requester The user requesting the revocation
     * @throws IllegalArgumentException if certificate or requester is null
     * @throws UnauthorizedException if the requester does not have permission to revoke
     * @throws IllegalStateException if the certificate is already revoked
     */
    public void validateRevocationRequest(Certificate certificate, User requester) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        if (requester == null) {
            throw new IllegalArgumentException("Requester cannot be null");
        }

        // Check if certificate is already revoked
        if (certificate.getStatus() == CertificateStatus.REVOKED) {
            throw new IllegalStateException("Certificate is already revoked");
        }

        // Check permission: requester must be owner, issuer, or ADMIN
        boolean hasPermission = false;

        // ADMIN can revoke any certificate
        if (requester.getRole() == Role.ADMIN) {
            hasPermission = true;
        }
        // Certificate owner can revoke their own certificate
        else if (certificate.getSignedBy() != null && certificate.getSignedBy().getId().equals(requester.getId())) {
            hasPermission = true;
        }
        // CA user can revoke certificates they issued
        else if (requester.getRole() == Role.CA_USER && certificate.getIssuerCertificate() != null &&
                 certificate.getIssuerCertificate().getSignedBy() != null &&
                 certificate.getIssuerCertificate().getSignedBy().getId().equals(requester.getId())) {
            hasPermission = true;
        }

        if (!hasPermission) {
            throw new UnauthorizedException("User does not have permission to revoke this certificate");
        }
    }

    /**
     * Validates Distinguished Name (DN) field values according to X.500 standards.
     * 
     * @param cn Common Name (required)
     * @param o Organization (optional)
     * @param ou Organizational Unit (optional)
     * @param l Locality (optional)
     * @param st State/Province (optional)
     * @param c Country code (optional, must be 2-letter ISO 3166-1)
     * @param e Email (optional, must be valid format)
     * @throws ValidationException if any field violates X.500 standards
     */
    public void validateDistinguishedName(String cn, String o, String ou, String l, String st, String c, String e) {
        // Validate Common Name (required)
        if (cn == null || cn.trim().isEmpty()) {
            throw new ValidationException("Common Name (CN) is required");
        }

        // Validate Country code (if provided, must be 2-letter ISO code)
        if (c != null && !c.trim().isEmpty()) {
            if (!Pattern.matches("^[A-Z]{2}$", c)) {
                throw new ValidationException("Country code must be a 2-letter ISO code: " + c);
            }
        }

        // Validate Email format (if provided)
        if (e != null && !e.trim().isEmpty()) {
            String emailPattern = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
            if (!Pattern.matches(emailPattern, e)) {
                throw new ValidationException("Invalid email format: " + e);
            }
        }
    }

    /**
     * Validates that key usage values are appropriate for the certificate type.
     * 
     * @param keyUsage List of key usage strings
     * @param isCA Whether this is a CA certificate
     * @throws ValidationException if key usage is invalid for the certificate type
     */
    public void validateKeyUsage(List<String> keyUsage, boolean isCA) {
        if (keyUsage == null || keyUsage.isEmpty()) {
            throw new ValidationException("Key usage cannot be empty");
        }

        // Check for CA-only usages in non-CA certificates
        if (!isCA) {
            for (String usage : keyUsage) {
                if ("keyCertSign".equals(usage) || "cRLSign".equals(usage)) {
                    throw new ValidationException("CA-only key usage '" + usage + "' not allowed for end-entity certificates");
                }
            }
        } else {
            // CA certificates must have keyCertSign
            if (!keyUsage.contains("keyCertSign")) {
                throw new ValidationException("CA certificates must have keyCertSign key usage");
            }
        }
    }

    /**
     * Validates that a regex pattern is valid and can be compiled.
     * 
     * @param pattern The regex pattern to validate
     * @param fieldName The name of the field (for error messages)
     * @throws ValidationException if the pattern is invalid
     */
    public void validateRegexPattern(String pattern, String fieldName) {
        if (pattern == null) {
            throw new ValidationException("Pattern cannot be null for field: " + fieldName);
        }
        if (pattern.trim().isEmpty()) {
            throw new ValidationException("Pattern cannot be empty for field: " + fieldName);
        }

        try {
            Pattern.compile(pattern);
        } catch (java.util.regex.PatternSyntaxException e) {
            throw new ValidationException("Invalid regex pattern for field '" + fieldName + "': " + e.getMessage());
        }
    }
}

