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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ValidationService Tests")
class ValidationServiceTest {

    @Mock
    private CertificateSignerService certificateSignerService;

    private ValidationService validationService;

    @BeforeEach
    void setUp() {
        validationService = new ValidationService(certificateSignerService);
    }

    @Nested
    @DisplayName("validateIssuerCertificate Tests")
    class ValidateIssuerCertificateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when issuer is null")
        void shouldThrowExceptionWhenIssuerIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateIssuerCertificate(null),
                "Should throw IllegalArgumentException when issuer is null"
            );

            assertEquals("Issuer certificate cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw InvalidCertificateException when certificate type is END_ENTITY")
        void shouldThrowExceptionWhenCertificateTypeIsEndEntity() {
            // Given
            Certificate issuer = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);

            // When & Then
            assertThrows(
                InvalidCertificateException.class,
                () -> validationService.validateIssuerCertificate(issuer),
                "Should throw InvalidCertificateException for end entity certificate"
            );
        }

        @Test
        @DisplayName("Should throw InvalidCertificateException when certificate status is REVOKED")
        void shouldThrowExceptionWhenCertificateStatusIsRevoked() {
            // Given
            Certificate issuer = createCertificate(CertificateType.ROOT, CertificateStatus.REVOKED);

            // When & Then
            assertThrows(
                InvalidCertificateException.class,
                () -> validationService.validateIssuerCertificate(issuer),
                "Should throw InvalidCertificateException for revoked certificate"
            );
        }

        @Test
        @DisplayName("Should throw InvalidCertificateException when certificate is expired")
        void shouldThrowExceptionWhenCertificateIsExpired() {
            // Given
            Certificate issuer = createExpiredCertificate(CertificateType.ROOT);

            // When & Then
            assertThrows(
                InvalidCertificateException.class,
                () -> validationService.validateIssuerCertificate(issuer),
                "Should throw InvalidCertificateException for expired certificate"
            );
        }

        @Test
        @DisplayName("Should throw InvalidCertificateException when certificate is not yet valid")
        void shouldThrowExceptionWhenCertificateIsNotYetValid() {
            // Given
            Certificate issuer = createFutureCertificate(CertificateType.ROOT);

            // When & Then
            assertThrows(
                InvalidCertificateException.class,
                () -> validationService.validateIssuerCertificate(issuer),
                "Should throw InvalidCertificateException for not yet valid certificate"
            );
        }

        @Test
        @DisplayName("Should throw InvalidCertificateException when keyUsage does not contain keyCertSign")
        void shouldThrowExceptionWhenKeyUsageDoesNotContainKeyCertSign() {
            // Given
            Certificate issuer = createCertificate(CertificateType.ROOT, CertificateStatus.VALID);
            issuer.setKeyUsage("digitalSignature,keyEncipherment"); // Missing keyCertSign

            // When & Then
            assertThrows(
                InvalidCertificateException.class,
                () -> validationService.validateIssuerCertificate(issuer),
                "Should throw InvalidCertificateException for missing keyCertSign"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid ROOT certificate")
        void shouldValidateSuccessfullyForValidRootCertificate() {
            // Given
            Certificate issuer = createValidCACertificate(CertificateType.ROOT);

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateIssuerCertificate(issuer),
                "Should not throw any exception for valid root certificate"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid INTERMEDIATE certificate")
        void shouldValidateSuccessfullyForValidIntermediateCertificate() {
            // Given
            Certificate issuer = createValidCACertificate(CertificateType.INTERMEDIATE);

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateIssuerCertificate(issuer),
                "Should not throw any exception for valid intermediate certificate"
            );
        }
    }

    @Nested
    @DisplayName("validateCertificateChain Tests")
    class ValidateCertificateChainTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificate is null")
        void shouldThrowExceptionWhenCertificateIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateCertificateChain(null),
                "Should throw IllegalArgumentException when certificate is null"
            );

            assertEquals("Certificate cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw InvalidCertificateException when chain is broken")
        void shouldThrowExceptionWhenChainIsBroken() {
            // Given
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            Certificate revokedIntermediate = createValidCACertificate(CertificateType.INTERMEDIATE);
            revokedIntermediate.setStatus(CertificateStatus.REVOKED);
            certificate.setIssuerCertificate(revokedIntermediate);

            // When & Then
            assertThrows(
                InvalidCertificateException.class,
                () -> validationService.validateCertificateChain(certificate),
                "Should throw InvalidCertificateException for broken chain (revoked issuer)"
            );
        }

        @Test
        @DisplayName("Should throw InvalidCertificateChainException when chain does not terminate at root")
        void shouldThrowExceptionWhenChainDoesNotTerminateAtRoot() {
            // Given
            Certificate endEntity = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            Certificate intermediate = createValidCACertificate(CertificateType.INTERMEDIATE);
            intermediate.setIssuerCertificate(createValidCACertificate(CertificateType.INTERMEDIATE));
            endEntity.setIssuerCertificate(intermediate);

            // When & Then
            assertThrows(
                InvalidCertificateChainException.class,
                () -> validationService.validateCertificateChain(endEntity),
                "Should throw InvalidCertificateChainException for chain not terminating at root"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid certificate chain")
        void shouldValidateSuccessfullyForValidCertificateChain() {
            // Given
            Certificate root = createValidCACertificate(CertificateType.ROOT);
            root.setIssuerCertificate(root); // Self-signed root
            root.setSubjectDN("CN=Test Root, O=Test Organization, C=US");
            root.setIssuerDN("CN=Test Root, O=Test Organization, C=US"); // Same as subject for self-signed
            
            Certificate intermediate = createValidCACertificate(CertificateType.INTERMEDIATE);
            intermediate.setIssuerCertificate(root);
            intermediate.setSubjectDN("CN=Test Intermediate, O=Test Organization, C=US");
            intermediate.setIssuerDN("CN=Test Root, O=Test Organization, C=US");
            
            Certificate endEntity = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            endEntity.setIssuerCertificate(intermediate);
            endEntity.setSubjectDN("CN=Test End Entity, O=Test Organization, C=US");
            endEntity.setIssuerDN("CN=Test Intermediate, O=Test Organization, C=US");

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateCertificateChain(endEntity),
                "Should not throw exception for valid certificate chain"
            );
        }
    }

    @Nested
    @DisplayName("validateTemplateConstraints Tests")
    class ValidateTemplateConstraintsTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when template is null")
        void shouldThrowExceptionWhenTemplateIsNull() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateTemplateConstraints(null, request),
                "Should throw IllegalArgumentException when template is null"
            );

            assertEquals("Template cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Given
            CertificateTemplate template = createTemplate();

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateTemplateConstraints(template, null),
                "Should throw IllegalArgumentException when request is null"
            );

            assertEquals("Request cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw TemplateConstraintViolationException when CN does not match pattern")
        void shouldThrowExceptionWhenCNDoesNotMatchPattern() {
            // Given
            CertificateTemplate template = createTemplate();
            template.setCommonNamePattern("^[A-Za-z0-9]+$");
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setSubjectCN("invalid-name-with-dashes");

            // When & Then
            assertThrows(
                TemplateConstraintViolationException.class,
                () -> validationService.validateTemplateConstraints(template, request),
                "Should throw TemplateConstraintViolationException for constraint violation"
            );
        }

        @Test
        @DisplayName("Should throw TemplateConstraintViolationException when validityDays exceeds TTL")
        void shouldThrowExceptionWhenValidityDaysExceedsTTL() {
            // Given
            CertificateTemplate template = createTemplate();
            template.setTtlDays(30);
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setValidityDays(60);

            // When & Then
            assertThrows(
                TemplateConstraintViolationException.class,
                () -> validationService.validateTemplateConstraints(template, request),
                "Should throw TemplateConstraintViolationException for constraint violation"
            );
        }

        @Test
        @DisplayName("Should validate successfully when all constraints are met")
        void shouldValidateSuccessfullyWhenAllConstraintsAreMet() {
            // Given
            CertificateTemplate template = createTemplate();
            template.setCommonNamePattern("^[A-Za-z0-9]+$");
            template.setTtlDays(365);
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setSubjectCN("validname123");
            request.setValidityDays(180);

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateTemplateConstraints(template, request),
                "Should not throw exception when all constraints are met"
            );
        }
    }

    @Nested
    @DisplayName("validateCertificateRequest Tests")
    class ValidateCertificateRequestTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Given
            User requester = createUser(Role.ADMIN);

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateCertificateRequest(null, requester),
                "Should throw IllegalArgumentException when request is null"
            );

            assertEquals("Request cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateCertificateRequest(request, null),
                "Should throw IllegalArgumentException when requester is null"
            );

            assertEquals("Requester cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw ValidationException when CN is empty")
        void shouldThrowExceptionWhenCNIsEmpty() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setSubjectCN("");
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateCertificateRequest(request, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when country code is invalid")
        void shouldThrowExceptionWhenCountryCodeIsInvalid() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setSubjectC("INVALID");
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateCertificateRequest(request, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when email format is invalid")
        void shouldThrowExceptionWhenEmailFormatIsInvalid() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setSubjectE("invalid-email");
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateCertificateRequest(request, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when keyUsage contains CA-only usages")
        void shouldThrowExceptionWhenKeyUsageContainsCAOnlyUsages() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            request.setKeyUsage(Arrays.asList("digitalSignature", "keyCertSign"));
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateCertificateRequest(request, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid request")
        void shouldValidateSuccessfullyForValidRequest() {
            // Given
            CreateEndEntityCertificateDTO request = createEndEntityCertificateRequest();
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateCertificateRequest(request, requester),
                "Should not throw exception for valid request"
            );
        }
    }

    @Nested
    @DisplayName("validateRevocationRequest Tests")
    class ValidateRevocationRequestTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificate is null")
        void shouldThrowExceptionWhenCertificateIsNull() {
            // Given
            User requester = createUser(Role.ADMIN);

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateRevocationRequest(null, requester),
                "Should throw IllegalArgumentException when certificate is null"
            );

            assertEquals("Certificate cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateRevocationRequest(certificate, null),
                "Should throw IllegalArgumentException when requester is null"
            );

            assertEquals("Requester cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalStateException when certificate is already revoked")
        void shouldThrowExceptionWhenCertificateIsAlreadyRevoked() {
            // Given
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.REVOKED);
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                IllegalStateException.class,
                () -> validationService.validateRevocationRequest(certificate, requester),
                "Should throw IllegalStateException for already revoked certificate"
            );
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when requester has no permission")
        void shouldThrowExceptionWhenRequesterHasNoPermission() {
            // Given
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            User owner = createUser(Role.REGULAR_USER);
            owner.setId(1L);
            certificate.setOwner(owner);
            
            User requester = createUser(Role.REGULAR_USER);
            requester.setId(2L); // Different ID

            // When & Then
            assertThrows(
                UnauthorizedException.class,
                () -> validationService.validateRevocationRequest(certificate, requester),
                "Should throw UnauthorizedException when requester has no permission"
            );
        }

        @Test
        @DisplayName("Should validate successfully when requester is certificate owner")
        void shouldValidateSuccessfullyWhenRequesterIsCertificateOwner() {
            // Given
            User owner = createUser(Role.REGULAR_USER);
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            certificate.setOwner(owner);

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateRevocationRequest(certificate, owner),
                "Should not throw exception when requester is certificate owner"
            );
        }

        @Test
        @DisplayName("Should validate successfully when requester is ADMIN")
        void shouldValidateSuccessfullyWhenRequesterIsAdmin() {
            // Given
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateRevocationRequest(certificate, admin),
                "Should not throw exception when requester is admin"
            );
        }
    }

    @Nested
    @DisplayName("validateDistinguishedName Tests")
    class ValidateDistinguishedNameTests {

        @Test
        @DisplayName("Should throw ValidationException when CN is null")
        void shouldThrowExceptionWhenCNIsNull() {
            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateDistinguishedName(null, "Org", "OU", "City", "State", "US", "test@example.com"),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when country code is not 2 letters")
        void shouldThrowExceptionWhenCountryCodeIsNotTwoLetters() {
            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateDistinguishedName("CN", "Org", "OU", "City", "State", "USA", "test@example.com"),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when email format is invalid")
        void shouldThrowExceptionWhenEmailFormatIsInvalid() {
            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateDistinguishedName("CN", "Org", "OU", "City", "State", "US", "invalid-email"),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid DN fields")
        void shouldValidateSuccessfullyForValidDNFields() {
            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateDistinguishedName("Test CN", "Test Org", "Test OU", "Test City", "Test State", "US", "test@example.com"),
                "Should not throw exception for valid DN fields"
            );
        }
    }

    @Nested
    @DisplayName("validateKeyUsage Tests")
    class ValidateKeyUsageTests {

        @Test
        @DisplayName("Should throw ValidationException when CA certificate has no keyCertSign")
        void shouldThrowExceptionWhenCACertificateHasNoKeyCertSign() {
            // Given
            List<String> keyUsage = Arrays.asList("digitalSignature", "keyEncipherment");

            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateKeyUsage(keyUsage, true),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when end-entity certificate has keyCertSign")
        void shouldThrowExceptionWhenEndEntityCertificateHasKeyCertSign() {
            // Given
            List<String> keyUsage = Arrays.asList("digitalSignature", "keyCertSign");

            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateKeyUsage(keyUsage, false),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid CA key usage")
        void shouldValidateSuccessfullyForValidCAKeyUsage() {
            // Given
            List<String> keyUsage = Arrays.asList("digitalSignature", "keyCertSign", "cRLSign");

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateKeyUsage(keyUsage, true),
                "Should not throw exception for valid CA key usage"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid end-entity key usage")
        void shouldValidateSuccessfullyForValidEndEntityKeyUsage() {
            // Given
            List<String> keyUsage = Arrays.asList("digitalSignature", "keyEncipherment");

            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateKeyUsage(keyUsage, false),
                "Should not throw exception for valid end-entity key usage"
            );
        }
    }

    @Nested
    @DisplayName("validateRegexPattern Tests")
    class ValidateRegexPatternTests {

        @Test
        @DisplayName("Should throw ValidationException when pattern is null")
        void shouldThrowExceptionWhenPatternIsNull() {
            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateRegexPattern(null, "testField"),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when pattern is empty")
        void shouldThrowExceptionWhenPatternIsEmpty() {
            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateRegexPattern("", "testField"),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when pattern is invalid regex")
        void shouldThrowExceptionWhenPatternIsInvalidRegex() {
            // When & Then
            assertThrows(
                ValidationException.class,
                () -> validationService.validateRegexPattern("[invalid", "testField"),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should validate successfully for valid regex pattern")
        void shouldValidateSuccessfullyForValidRegexPattern() {
            // When & Then
            assertDoesNotThrow(
                () -> validationService.validateRegexPattern("^[A-Za-z0-9]+$", "testField"),
                "Should not throw exception for valid regex pattern"
            );
        }
    }

    // Helper methods for creating test objects
    private Certificate createCertificate(CertificateType type, CertificateStatus status) {
        Certificate certificate = new Certificate();
        certificate.setCertificateType(type);
        certificate.setStatus(status);
        certificate.setSerialNumber("1234567890");
        certificate.setSubjectCN("Test Certificate");
        certificate.setSubjectO("Test Organization");
        certificate.setSubjectOU("Test OU");
        certificate.setSubjectL("Test City");
        certificate.setSubjectST("Test State");
        certificate.setSubjectC("US");
        certificate.setSubjectE("test@example.com");
        certificate.setValidFrom(LocalDateTime.now().minusDays(1));
        certificate.setValidTo(LocalDateTime.now().plusDays(365));
        certificate.setKeyUsage("digitalSignature,keyEncipherment");
        return certificate;
    }

    private Certificate createValidCACertificate(CertificateType type) {
        Certificate certificate = createCertificate(type, CertificateStatus.VALID);
        certificate.setKeyUsage("digitalSignature,keyCertSign,cRLSign");
        return certificate;
    }

    private Certificate createExpiredCertificate(CertificateType type) {
        Certificate certificate = createCertificate(type, CertificateStatus.VALID);
        certificate.setValidFrom(LocalDateTime.now().minusDays(2));
        certificate.setValidTo(LocalDateTime.now().minusDays(1));
        return certificate;
    }

    private Certificate createFutureCertificate(CertificateType type) {
        Certificate certificate = createCertificate(type, CertificateStatus.VALID);
        certificate.setValidFrom(LocalDateTime.now().plusDays(1));
        certificate.setValidTo(LocalDateTime.now().plusDays(366));
        return certificate;
    }

    private CertificateTemplate createTemplate() {
        CertificateTemplate template = new CertificateTemplate();
        template.setId(1L);
        template.setName("Test Template");
        template.setCommonNamePattern("^[A-Za-z0-9]+$");
        template.setSanPattern("^[A-Za-z0-9.]+$");
        template.setTtlDays(365);
        template.setKeyUsage("digitalSignature,keyEncipherment");
        template.setExtendedKeyUsage("serverAuth,clientAuth");
        return template;
    }

    private CreateEndEntityCertificateDTO createEndEntityCertificateRequest() {
        CreateEndEntityCertificateDTO request = new CreateEndEntityCertificateDTO();
        request.setIssuerCertificateId(1L);
        request.setSubjectCN("Test Certificate");
        request.setSubjectO("Test Organization");
        request.setSubjectOU("Test OU");
        request.setSubjectL("Test City");
        request.setSubjectST("Test State");
        request.setSubjectC("US");
        request.setSubjectE("test@example.com");
        request.setValidityDays(365);
        request.setKeySize(2048);
        request.setKeyUsage(Arrays.asList("digitalSignature", "keyEncipherment"));
        request.setExtendedKeyUsage(Arrays.asList("serverAuth", "clientAuth"));
        request.setSubjectAlternativeNames(Arrays.asList("test.example.com", "192.168.1.1"));
        return request;
    }

    private User createUser(Role role) {
        User user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setFirstName("Test");
        user.setLastName("User");
        user.setPasswordHash("hashedpassword");
        user.setRole(role);
        return user;
    }
}
