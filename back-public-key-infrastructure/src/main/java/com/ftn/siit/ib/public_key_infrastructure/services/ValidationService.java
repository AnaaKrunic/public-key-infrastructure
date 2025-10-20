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
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Pattern;
import java.security.cert.X509Certificate;

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
    private final CRLService crlService;

    public ValidationService(CertificateSignerService certificateSignerService, CRLService crlService) {
        this.certificateSignerService = certificateSignerService;
        this.crlService = crlService;
    }

    /**
     * Validates that a certificate is a valid CA certificate that can issue other certificates.
     * 
     * Validation checks:
     * - Certificate type must be ROOT or INTERMEDIATE
     * - Certificate status must be VALID (not REVOKED)
     * - Certificate must NOT be revoked (checks CRL Distribution Point)
     * - Certificate must be within its validity period (notBefore <= now <= notAfter)
     * - Certificate must have keyCertSign key usage
     * - Digital signature must be valid (self-signed for ROOT, signed by issuer for INTERMEDIATE)
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

        // Check revocation status via CRL Distribution Point
        boolean isRevoked = crlService.checkCertificateRevocationViaCRL(issuer);
        if (isRevoked) {
            throw new InvalidCertificateException(
                "Certificate has been revoked and cannot be used to sign other certificates. " +
                "Certificate serial number: " + issuer.getSerialNumber()
            );
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

        // Verify digital signature
        try {
            X509Certificate x509Cert = parseX509CertificateFromPEM(issuer.getCertificateData());
            
            // For root certificates (self-signed), verify against own public key
            if (issuer.getCertificateType() == CertificateType.ROOT) {
                if (!certificateSignerService.verifyCertificateSignature(x509Cert, x509Cert.getPublicKey())) {
                    throw new InvalidCertificateException("Root certificate has invalid self-signature");
                }
            } 
            // For intermediate certificates, verify against issuer's public key
            else if (issuer.getCertificateType() == CertificateType.INTERMEDIATE) {
                if (issuer.getIssuerCertificate() == null) {
                    throw new InvalidCertificateException("Intermediate certificate must have an issuer certificate");
                }
                
                X509Certificate issuerX509Cert = parseX509CertificateFromPEM(
                    issuer.getIssuerCertificate().getCertificateData()
                );
                
                if (!certificateSignerService.verifyCertificateSignature(x509Cert, issuerX509Cert.getPublicKey())) {
                    throw new InvalidCertificateException("Certificate signature verification failed");
                }
            }
        } catch (InvalidCertificateException e) {
            throw e; // Re-throw our custom exceptions
        } catch (Exception e) {
            throw new InvalidCertificateException("Failed to verify certificate signature: " + e.getMessage());
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
        if (template.getCnRegex() != null && !template.getCnRegex().trim().isEmpty()) {
            if (request.getSubjectCN() == null || !Pattern.matches(template.getCnRegex(), request.getSubjectCN())) {
                throw new TemplateConstraintViolationException(
                    "Subject CN '" + request.getSubjectCN() + "' does not match template pattern '" + template.getCnRegex() + "'");
            }
        }

        // Validate Subject Alternative Names pattern
        if (template.getSanRegex() != null && !template.getSanRegex().trim().isEmpty()) {
            if (request.getSubjectAlternativeNames() != null) {
                for (String san : request.getSubjectAlternativeNames()) {
                    if (!Pattern.matches(template.getSanRegex(), san)) {
                        throw new TemplateConstraintViolationException(
                            "Subject Alternative Name '" + san + "' does not match template pattern '" + template.getSanRegex() + "'");
                    }
                }
            }
        }

        // Validate validity days
        if (template.getTtl() != null && request.getValidityDays() != null) {
            if (request.getValidityDays() > template.getTtl()) {
                throw new TemplateConstraintViolationException(
                    "Requested validity days (" + request.getValidityDays() + ") exceeds template limit (" + template.getTtl() + ")");
            }
        }

        // Validate issuer certificate matches
        if (template.getCaIssuerSerialNumber() != null && request.getIssuerCertificateId() != null) {
            // Note: This validation would need to be implemented differently since we're comparing
            // a serial number (String) with an ID (Long). For now, we'll skip this validation
            // or implement it in the service layer where we can fetch the certificate by ID
            // and compare serial numbers.
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
     * Validates that the issuer certificate's validity period covers the new certificate's validity period.
     * 
     * The new certificate must:
     * - Have a validFrom date that is on or after the issuer's validFrom
     * - Have a validTo date that is on or before the issuer's validTo
     * 
     * This ensures the new certificate cannot be valid outside the issuer's validity window.
     * 
     * @param issuer The issuer certificate
     * @param newCertValidFrom The validity start date of the new certificate
     * @param newCertValidTo The validity end date of the new certificate
     * @throws IllegalArgumentException if any parameter is null
     * @throws ValidationException if the validity period is invalid
     */
    public void validateCertificateValidityPeriod(Certificate issuer, LocalDateTime newCertValidFrom, LocalDateTime newCertValidTo) {
        if (issuer == null) {
            throw new IllegalArgumentException("Issuer certificate cannot be null");
        }
        if (newCertValidFrom == null) {
            throw new IllegalArgumentException("New certificate validFrom cannot be null");
        }
        if (newCertValidTo == null) {
            throw new IllegalArgumentException("New certificate validTo cannot be null");
        }

        // Check if new certificate's validFrom is before issuer's validFrom
        if (newCertValidFrom.isBefore(issuer.getValidFrom())) {
            throw new ValidationException(
                "Certificate cannot be valid before its issuer. " +
                "Certificate validFrom: " + newCertValidFrom + ", " +
                "Issuer validFrom: " + issuer.getValidFrom()
            );
        }

        // Check if new certificate's validTo is after issuer's validTo
        if (newCertValidTo.isAfter(issuer.getValidTo())) {
            throw new ValidationException(
                "Certificate cannot be valid after its issuer. " +
                "Certificate validTo: " + newCertValidTo + ", " +
                "Issuer validTo: " + issuer.getValidTo()
            );
        }

        // Verify the validity period is positive
        if (newCertValidFrom.isAfter(newCertValidTo) || newCertValidFrom.isEqual(newCertValidTo)) {
            throw new ValidationException(
                "Certificate validFrom must be before validTo. " +
                "ValidFrom: " + newCertValidFrom + ", ValidTo: " + newCertValidTo
            );
        }
    }

    /**
     * Validates that certificate extensions combined with template extensions
     * do not exceed the policy constraints of the signing certificate.
     * 
     * This method ensures that:
     * 1. Template extensions are included in the final certificate
     * 2. Additional extensions don't violate signing certificate policy
     * 3. Total extension set is valid for the certificate type
     * 
     * @param template The certificate template (can be null if no template used)
     * @param requestExtensions The additional extensions requested by user
     * @param signingCertificate The CA certificate that will sign the new certificate
     * @param certificateType The type of certificate being created
     * @throws ValidationException if extensions violate policy constraints
     */
    public void validateTemplateAndExtensionsPolicy(
            CertificateTemplate template,
            List<String> requestKeyUsage,
            List<String> requestExtendedKeyUsage,
            Certificate signingCertificate,
            CertificateType certificateType) {
        
        // Start with template extensions if template is provided
        Set<String> finalKeyUsage = new HashSet<>();
        Set<String> finalExtendedKeyUsage = new HashSet<>();
        
        // Add template extensions
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
        
        // Add user-requested extensions
        if (requestKeyUsage != null) {
            finalKeyUsage.addAll(requestKeyUsage);
        }
        if (requestExtendedKeyUsage != null) {
            finalExtendedKeyUsage.addAll(requestExtendedKeyUsage);
        }
        
        // Validate against signing certificate policy
        validateExtensionsAgainstSigningPolicy(finalKeyUsage, finalExtendedKeyUsage, signingCertificate, certificateType);
    }
    
    /**
     * Validates that the final set of extensions is allowed by the signing certificate's policy.
     * 
     * @param finalKeyUsage The complete key usage set
     * @param finalExtendedKeyUsage The complete extended key usage set
     * @param signingCertificate The CA certificate that will sign the new certificate
     * @param certificateType The type of certificate being created
     * @throws ValidationException if extensions violate policy constraints
     */
    private void validateExtensionsAgainstSigningPolicy(
            Set<String> finalKeyUsage,
            Set<String> finalExtendedKeyUsage,
            Certificate signingCertificate,
            CertificateType certificateType) {
        
        // For CA certificates (ROOT, INTERMEDIATE), ensure they can't issue certificates with
        // keyCertSign or cRLSign unless the signing certificate allows it
        if (certificateType == CertificateType.END_ENTITY) {
            if (finalKeyUsage.contains("keyCertSign") || finalKeyUsage.contains("cRLSign")) {
                throw new ValidationException(
                    "End-entity certificates cannot have keyCertSign or cRLSign key usage");
            }
        }
        
        // Validate that the signing certificate has the necessary key usage to sign this type of certificate
        if (signingCertificate.getKeyUsage() != null) {
            String signingKeyUsage = signingCertificate.getKeyUsage();
            
            // Check if signing certificate can issue certificates
            if (!signingKeyUsage.contains("keyCertSign")) {
                throw new ValidationException(
                    "Signing certificate does not have keyCertSign usage and cannot issue certificates");
            }
        }
        
        // Additional policy validations can be added here based on specific requirements
        // For example, checking if certain combinations of extensions are allowed
        validateExtensionCombinations(finalKeyUsage, finalExtendedKeyUsage, certificateType);
    }
    
    /**
     * Validates that extension combinations are valid for the certificate type.
     * 
     * @param keyUsage The key usage extensions
     * @param extendedKeyUsage The extended key usage extensions
     * @param certificateType The certificate type
     * @throws ValidationException if extension combinations are invalid
     */
    private void validateExtensionCombinations(
            Set<String> keyUsage,
            Set<String> extendedKeyUsage,
            CertificateType certificateType) {
        
        // Example validations - can be extended based on specific requirements
        
        // For end-entity certificates, ensure appropriate key usage combinations
        if (certificateType == CertificateType.END_ENTITY) {
            // If digitalSignature is present, dataEncipherment or keyEncipherment should be present for TLS
            if (keyUsage.contains("digitalSignature")) {
                if (!keyUsage.contains("keyEncipherment") && !keyUsage.contains("dataEncipherment")) {
                    // This is just a warning, not an error - some certificates might be valid without these
                    System.out.println("WARNING: digitalSignature without keyEncipherment or dataEncipherment may not be suitable for TLS");
                }
            }
        }
        
        // Validate that extended key usage values are valid
        Set<String> validExtendedKeyUsage = Set.of(
            "serverAuth", "clientAuth", "codeSigning", "emailProtection", 
            "timeStamping", "ocspSigning", "msCodeInd", "msCodeCom", "msCTLSign", "msSGC"
        );
        
        for (String eku : extendedKeyUsage) {
            if (!validExtendedKeyUsage.contains(eku)) {
                //asd
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
            String cleanPem = pemData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            
            byte[] derData = java.util.Base64.getDecoder().decode(cleanPem);
            java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
            
            return (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(derData)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse X.509 certificate from PEM: " + e.getMessage(), e);
        }
    }
}

