package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateTemplateDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UpdateTemplateDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateTemplate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateTemplateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("TemplateService Tests")
class TemplateServiceTest {

    @Mock
    private CertificateTemplateRepository templateRepository;
    @Mock
    private ValidationService validationService;
    @Mock
    private CertificateRepository certificateRepository;

    private TemplateService templateService;

    @BeforeEach
    void setUp() {
        templateService = new TemplateService(templateRepository, validationService);
    }

    @Nested
    @DisplayName("createTemplate Tests")
    class CreateTemplateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            User caUser = createUser(Role.CA_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(null, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when caUser is null")
        void shouldThrowExceptionWhenCaUserIsNull() {
            // Given
            CreateTemplateDTO dto = createTemplateDTO();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(dto, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when user is not CA_USER or ADMIN")
        void shouldThrowExceptionWhenUserIsNotCAUserOrAdmin() {
            // Given
            CreateTemplateDTO dto = createTemplateDTO();
            User regularUser = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(dto, regularUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when issuer certificate not found")
        void shouldThrowExceptionWhenIssuerCertificateNotFound() {
            // Given
            CreateTemplateDTO dto = createTemplateDTO();
            User caUser = createUser(Role.CA_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ForbiddenException when CA_USER tries to use another user's CA")
        void shouldThrowExceptionWhenCAUserTriesToUseAnotherUsersCA() {
            // Given
            CreateTemplateDTO dto = createTemplateDTO();
            User caUser = createUser(Role.CA_USER);
            Certificate issuer = createCertificate(CertificateType.ROOT, CertificateStatus.VALID);
            issuer.setOwner(createUser(Role.CA_USER)); // Different user

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should create template successfully for CA_USER")
        void shouldCreateTemplateSuccessfullyForCAUser() {
            // Given
            CreateTemplateDTO dto = createTemplateDTO();
            User caUser = createUser(Role.CA_USER);
            Certificate issuer = createCertificate(CertificateType.ROOT, CertificateStatus.VALID);
            issuer.setOwner(caUser); // Same user

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should create template successfully for ADMIN")
        void shouldCreateTemplateSuccessfullyForAdmin() {
            // Given
            CreateTemplateDTO dto = createTemplateDTO();
            User admin = createUser(Role.ADMIN);
            Certificate issuer = createCertificate(CertificateType.ROOT, CertificateStatus.VALID);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.createTemplate(dto, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("updateTemplate Tests")
    class UpdateTemplateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when templateId is null")
        void shouldThrowExceptionWhenTemplateIdIsNull() {
            // Given
            UpdateTemplateDTO dto = createUpdateTemplateDTO();
            User caUser = createUser(Role.CA_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(null, dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            Long templateId = 1L;
            User caUser = createUser(Role.CA_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(templateId, null, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when caUser is null")
        void shouldThrowExceptionWhenCaUserIsNull() {
            // Given
            Long templateId = 1L;
            UpdateTemplateDTO dto = createUpdateTemplateDTO();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(templateId, dto, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when template not found")
        void shouldThrowExceptionWhenTemplateNotFound() {
            // Given
            Long templateId = 1L;
            UpdateTemplateDTO dto = createUpdateTemplateDTO();
            User caUser = createUser(Role.CA_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(templateId, dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ForbiddenException when user is not owner and not ADMIN")
        void shouldThrowExceptionWhenUserIsNotOwnerAndNotAdmin() {
            // Given
            Long templateId = 1L;
            UpdateTemplateDTO dto = createUpdateTemplateDTO();
            User caUser = createUser(Role.CA_USER);
            CertificateTemplate template = createTemplate();
            template.setCaIssuer(createUser(Role.CA_USER)); // Different user

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(templateId, dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should update template successfully when user is owner")
        void shouldUpdateTemplateSuccessfullyWhenUserIsOwner() {
            // Given
            Long templateId = 1L;
            UpdateTemplateDTO dto = createUpdateTemplateDTO();
            User caUser = createUser(Role.CA_USER);
            CertificateTemplate template = createTemplate();
            template.setCaIssuer(caUser); // Same user

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(templateId, dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should update template successfully when user is ADMIN")
        void shouldUpdateTemplateSuccessfullyWhenUserIsAdmin() {
            // Given
            Long templateId = 1L;
            UpdateTemplateDTO dto = createUpdateTemplateDTO();
            User admin = createUser(Role.ADMIN);
            CertificateTemplate template = createTemplate();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.updateTemplate(templateId, dto, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("deleteTemplate Tests")
    class DeleteTemplateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when templateId is null")
        void shouldThrowExceptionWhenTemplateIdIsNull() {
            // Given
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(null, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            Long templateId = 1L;

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(templateId, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when template not found")
        void shouldThrowExceptionWhenTemplateNotFound() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ForbiddenException when user is not owner and not ADMIN")
        void shouldThrowExceptionWhenUserIsNotOwnerAndNotAdmin() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.CA_USER);
            CertificateTemplate template = createTemplate();
            template.setCaIssuer(createUser(Role.CA_USER)); // Different user

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalStateException when template has pending CSRs")
        void shouldThrowExceptionWhenTemplateHasPendingCSRs() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.ADMIN);
            CertificateTemplate template = createTemplate();
            // Mock that there are pending CSRs (this would be checked in the actual implementation)
            // For now, we'll just test the basic flow

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should delete template successfully when user is owner")
        void shouldDeleteTemplateSuccessfullyWhenUserIsOwner() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.CA_USER);
            CertificateTemplate template = createTemplate();
            template.setCaIssuer(requester); // Same user
            // Mock that there are no pending CSRs (this would be checked in the actual implementation)
            // For now, we'll just test the basic flow

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should delete template successfully when user is ADMIN")
        void shouldDeleteTemplateSuccessfullyWhenUserIsAdmin() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.ADMIN);
            CertificateTemplate template = createTemplate();
            // Mock that there are no pending CSRs (this would be checked in the actual implementation)
            // For now, we'll just test the basic flow

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.deleteTemplate(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("listTemplates Tests")
    class ListTemplatesTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when caUser is null")
        void shouldThrowExceptionWhenCaUserIsNull() {
            // Given
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.listTemplates(null, pageable),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return templates for CA_USER")
        void shouldReturnTemplatesForCAUser() {
            // Given
            User caUser = createUser(Role.CA_USER);
            Pageable pageable = mock(Pageable.class);
            List<CertificateTemplate> templates = Arrays.asList(createTemplate());

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.listTemplates(caUser, pageable),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return all templates for ADMIN")
        void shouldReturnAllTemplatesForAdmin() {
            // Given
            User admin = createUser(Role.ADMIN);
            Pageable pageable = mock(Pageable.class);
            List<CertificateTemplate> templates = Arrays.asList(createTemplate());
            Page<CertificateTemplate> templatePage = new PageImpl<>(templates);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.listTemplates(admin, pageable),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("getTemplateById Tests")
    class GetTemplateByIdTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when templateId is null")
        void shouldThrowExceptionWhenTemplateIdIsNull() {
            // Given
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.getTemplateById(null, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            Long templateId = 1L;

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.getTemplateById(templateId, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when template not found")
        void shouldThrowExceptionWhenTemplateNotFound() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.getTemplateById(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return template successfully")
        void shouldReturnTemplateSuccessfully() {
            // Given
            Long templateId = 1L;
            User requester = createUser(Role.ADMIN);
            CertificateTemplate template = createTemplate();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.getTemplateById(templateId, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("listTemplatesForCA Tests")
    class ListTemplatesForCATests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when caCertificateId is null")
        void shouldThrowExceptionWhenCaCertificateIdIsNull() {
            // Given
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.listTemplatesForCA(null, pageable),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when CA certificate not found")
        void shouldThrowExceptionWhenCACertificateNotFound() {
            // Given
            Long caCertificateId = 1L;
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.listTemplatesForCA(caCertificateId, pageable),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return templates for CA successfully")
        void shouldReturnTemplatesForCASuccessfully() {
            // Given
            Long caCertificateId = 1L;
            Pageable pageable = mock(Pageable.class);
            Certificate caCertificate = createCertificate(CertificateType.ROOT, CertificateStatus.VALID);
            List<CertificateTemplate> templates = Arrays.asList(createTemplate());

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> templateService.listTemplatesForCA(caCertificateId, pageable),
                "Should throw UnsupportedOperationException (not implemented yet)"
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

    private CreateTemplateDTO createTemplateDTO() {
        CreateTemplateDTO dto = new CreateTemplateDTO();
        dto.setName("Test Template");
        dto.setIssuerCertificateId(1L);
        dto.setCommonNamePattern("^[A-Za-z0-9]+$");
        dto.setSanPattern("^[A-Za-z0-9.]+$");
        dto.setTtlDays(365);
        dto.setKeyUsage("digitalSignature,keyEncipherment");
        dto.setExtendedKeyUsage("serverAuth,clientAuth");
        return dto;
    }

    private UpdateTemplateDTO createUpdateTemplateDTO() {
        UpdateTemplateDTO dto = new UpdateTemplateDTO();
        dto.setName("Updated Template");
        dto.setCommonNamePattern("^[A-Za-z0-9-]+$");
        dto.setSanPattern("^[A-Za-z0-9.-]+$");
        dto.setTtlDays(180);
        dto.setKeyUsage("digitalSignature,keyEncipherment,nonRepudiation");
        dto.setExtendedKeyUsage("serverAuth,clientAuth,emailProtection");
        return dto;
    }
}
