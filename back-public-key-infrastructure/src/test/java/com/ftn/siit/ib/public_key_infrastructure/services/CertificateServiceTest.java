package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.exceptions.UnauthorizedException;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.*;
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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService.EncryptedData;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CertificateService Tests")
class CertificateServiceTest {

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private ValidationService validationService;
    @Mock
    private CertificateGeneratorService certificateGeneratorService;
    @Mock
    private CertificateSignerService certificateSignerService;
    @Mock
    private EncryptionService encryptionService;
    @Mock
    private KeyPairGeneratorService keyPairGeneratorService;
    @Mock
    private KeystoreService keystoreService;
    @Mock
    private CRLService crlService;

    private CertificateService certificateService;

    @BeforeEach
    void setUp() {
        certificateService = new CertificateService(
            certificateRepository,
            validationService,
            certificateGeneratorService,
            certificateSignerService,
            encryptionService,
            keyPairGeneratorService,
            keystoreService,
            crlService
        );
    }

    @Nested
    @DisplayName("createRootCertificate Tests")
    class CreateRootCertificateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> certificateService.createRootCertificate(null, admin),
                "Should throw IllegalArgumentException when DTO is null"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when admin is null")
        void shouldThrowExceptionWhenAdminIsNull() {
            // Given
            CreateRootCertificateDTO dto = createRootCertificateDTO();

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> certificateService.createRootCertificate(dto, null),
                "Should throw IllegalArgumentException when admin is null"
            );
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when user is not ADMIN")
        void shouldThrowExceptionWhenUserIsNotAdmin() {
            // Given
            CreateRootCertificateDTO dto = createRootCertificateDTO();
            User regularUser = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                UnauthorizedException.class,
                () -> certificateService.createRootCertificate(dto, regularUser),
                "Should throw UnauthorizedException when user is not ADMIN"
            );
        }

        @Test
        @DisplayName("Should create root certificate successfully for ADMIN")
        void shouldCreateRootCertificateSuccessfullyForAdmin() {
            // Given
            CreateRootCertificateDTO dto = createRootCertificateDTO();
            User admin = createUser(Role.ADMIN);
            
            // Mock the crypto services
            when(keyPairGeneratorService.generateKeyPair(anyInt())).thenReturn(mock(KeyPair.class));
            when(certificateGeneratorService.buildX500Name(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(mock(X500Name.class));
            X509Certificate mockCertificate = mock(X509Certificate.class);
            when(mockCertificate.getSerialNumber()).thenReturn(java.math.BigInteger.valueOf(12345));
            when(certificateGeneratorService.generateRootCertificate(any(), any(), anyInt(), any(), any()))
                .thenReturn(mockCertificate);
            EncryptedData mockEncryptedData = new EncryptedData(
                "encrypted-data".getBytes(),
                "iv-data".getBytes(),
                "tag-data".getBytes()
            );
            when(encryptionService.encryptPrivateKey(any(), any())).thenReturn(mockEncryptedData);
            when(keystoreService.exportPublicKeyAsPEM(any())).thenReturn("-----BEGIN PUBLIC KEY-----");
            when(keystoreService.exportCertificateAsPEM(any())).thenReturn("-----BEGIN CERTIFICATE-----");
            when(certificateRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

            // When
            CertificateDTO result = certificateService.createRootCertificate(dto, admin);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(dto.getSubjectCN(), result.getSubjectCN(), "Subject CN should match");
            assertEquals(dto.getSubjectO(), result.getSubjectO(), "Subject O should match");
            assertEquals(CertificateType.ROOT, result.getCertificateType(), "Certificate type should be ROOT");
            assertEquals(CertificateStatus.VALID, result.getStatus(), "Status should be VALID");
        }
    }

    @Nested
    @DisplayName("createIntermediateCertificate Tests")
    class CreateIntermediateCertificateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createIntermediateCertificate(null, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when admin is null")
        void shouldThrowExceptionWhenAdminIsNull() {
            // Given
            CreateIntermediateCertificateDTO dto = createIntermediateCertificateDTO();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createIntermediateCertificate(dto, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when user is not ADMIN")
        void shouldThrowExceptionWhenUserIsNotAdmin() {
            // Given
            CreateIntermediateCertificateDTO dto = createIntermediateCertificateDTO();
            User regularUser = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createIntermediateCertificate(dto, regularUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when issuer certificate not found")
        void shouldThrowExceptionWhenIssuerCertificateNotFound() {
            // Given
            CreateIntermediateCertificateDTO dto = createIntermediateCertificateDTO();
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createIntermediateCertificate(dto, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should create intermediate certificate successfully")
        void shouldCreateIntermediateCertificateSuccessfully() {
            // Given
            CreateIntermediateCertificateDTO dto = createIntermediateCertificateDTO();
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createIntermediateCertificate(dto, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("createEndEntityCertificate Tests")
    class CreateEndEntityCertificateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createEndEntityCertificate(null, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            CreateEndEntityCertificateDTO dto = createEndEntityCertificateDTO();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createEndEntityCertificate(dto, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw UnauthorizedException when REGULAR_USER tries to create certificate")
        void shouldThrowExceptionWhenRegularUserTriesToCreateCertificate() {
            // Given
            CreateEndEntityCertificateDTO dto = createEndEntityCertificateDTO();
            User regularUser = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createEndEntityCertificate(dto, regularUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should create end-entity certificate successfully for ADMIN")
        void shouldCreateEndEntityCertificateSuccessfullyForAdmin() {
            // Given
            CreateEndEntityCertificateDTO dto = createEndEntityCertificateDTO();
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createEndEntityCertificate(dto, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should create end-entity certificate successfully for CA_USER")
        void shouldCreateEndEntityCertificateSuccessfullyForCAUser() {
            // Given
            CreateEndEntityCertificateDTO dto = createEndEntityCertificateDTO();
            User caUser = createUser(Role.CA_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.createEndEntityCertificate(dto, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("getCertificateBySerialNumber Tests")
    class GetCertificateBySerialNumberTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when serialNumber is null")
        void shouldThrowExceptionWhenSerialNumberIsNull() {
            // Given
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateBySerialNumber(null, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            String serialNumber = "1234567890";

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateBySerialNumber(serialNumber, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when certificate not found")
        void shouldThrowExceptionWhenCertificateNotFound() {
            // Given
            String serialNumber = "1234567890";
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateBySerialNumber(serialNumber, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ForbiddenException when REGULAR_USER tries to access other user's certificate")
        void shouldThrowExceptionWhenRegularUserTriesToAccessOtherUsersCertificate() {
            // Given
            String serialNumber = "1234567890";
            User requester = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateBySerialNumber(serialNumber, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return certificate when ADMIN accesses any certificate")
        void shouldReturnCertificateWhenAdminAccessesAnyCertificate() {
            // Given
            String serialNumber = "1234567890";
            User admin = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateBySerialNumber(serialNumber, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return certificate when REGULAR_USER accesses own certificate")
        void shouldReturnCertificateWhenRegularUserAccessesOwnCertificate() {
            // Given
            String serialNumber = "1234567890";
            User requester = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateBySerialNumber(serialNumber, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("listCertificates Tests")
    class ListCertificatesTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.listCertificates(CertificateType.END_ENTITY, CertificateStatus.VALID, pageable, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return all certificates for ADMIN")
        void shouldReturnAllCertificatesForAdmin() {
            // Given
            User admin = createUser(Role.ADMIN);
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.listCertificates(null, null, pageable, admin),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return filtered certificates for CA_USER")
        void shouldReturnFilteredCertificatesForCAUser() {
            // Given
            User caUser = createUser(Role.CA_USER);
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.listCertificates(CertificateType.END_ENTITY, CertificateStatus.VALID, pageable, caUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return own certificates for REGULAR_USER")
        void shouldReturnOwnCertificatesForRegularUser() {
            // Given
            User regularUser = createUser(Role.REGULAR_USER);
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.listCertificates(null, null, pageable, regularUser),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("getCertificateChain Tests")
    class GetCertificateChainTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when serialNumber is null")
        void shouldThrowExceptionWhenSerialNumberIsNull() {
            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateChain(null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when certificate not found")
        void shouldThrowExceptionWhenCertificateNotFound() {
            // Given
            String serialNumber = "1234567890";

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateChain(serialNumber),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should return certificate chain successfully")
        void shouldReturnCertificateChainSuccessfully() {
            // Given
            String serialNumber = "1234567890";

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.getCertificateChain(serialNumber),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("revokeCertificate Tests")
    class RevokeCertificateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when serialNumber is null")
        void shouldThrowExceptionWhenSerialNumberIsNull() {
            // Given
            RevokeCertificateDTO dto = createRevokeCertificateDTO();
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.revokeCertificate(null, dto, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            String serialNumber = "1234567890";
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.revokeCertificate(serialNumber, null, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            String serialNumber = "1234567890";
            RevokeCertificateDTO dto = createRevokeCertificateDTO();

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.revokeCertificate(serialNumber, dto, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when certificate not found")
        void shouldThrowExceptionWhenCertificateNotFound() {
            // Given
            String serialNumber = "1234567890";
            RevokeCertificateDTO dto = createRevokeCertificateDTO();
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.revokeCertificate(serialNumber, dto, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalStateException when certificate is already revoked")
        void shouldThrowExceptionWhenCertificateAlreadyRevoked() {
            // Given
            String serialNumber = "1234567890";
            RevokeCertificateDTO dto = createRevokeCertificateDTO();
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.revokeCertificate(serialNumber, dto, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should revoke certificate successfully")
        void shouldRevokeCertificateSuccessfully() {
            // Given
            String serialNumber = "1234567890";
            RevokeCertificateDTO dto = createRevokeCertificateDTO();
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.revokeCertificate(serialNumber, dto, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }
    }

    @Nested
    @DisplayName("downloadCertificate Tests")
    class DownloadCertificateTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when serialNumber is null")
        void shouldThrowExceptionWhenSerialNumberIsNull() {
            // Given
            String format = "PKCS12";
            String password = "password";
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(null, format, password, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when format is null")
        void shouldThrowExceptionWhenFormatIsNull() {
            // Given
            String serialNumber = "1234567890";
            String password = "password";
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, null, password, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            String serialNumber = "1234567890";
            String format = "PKCS12";
            String password = "password";

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, format, password, null),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw NotFoundException when certificate not found")
        void shouldThrowExceptionWhenCertificateNotFound() {
            // Given
            String serialNumber = "1234567890";
            String format = "PKCS12";
            String password = "password";
            User requester = createUser(Role.ADMIN);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, format, password, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ForbiddenException when requester is not owner and not ADMIN")
        void shouldThrowExceptionWhenRequesterIsNotOwnerAndNotAdmin() {
            // Given
            String serialNumber = "1234567890";
            String format = "PKCS12";
            String password = "password";
            User requester = createUser(Role.REGULAR_USER);
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);
            certificate.setOwner(createUser(Role.REGULAR_USER)); // Different user

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, format, password, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should throw ValidationException when password is missing for PKCS12 format")
        void shouldThrowExceptionWhenPasswordIsMissingForPKCS12Format() {
            // Given
            String serialNumber = "1234567890";
            String format = "PKCS12";
            String password = null; // Missing password
            User requester = createUser(Role.ADMIN);
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, format, password, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should download certificate successfully for PKCS12 format")
        void shouldDownloadCertificateSuccessfullyForPKCS12Format() {
            // Given
            String serialNumber = "1234567890";
            String format = "PKCS12";
            String password = "password";
            User requester = createUser(Role.ADMIN);
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, format, password, requester),
                "Should throw UnsupportedOperationException (not implemented yet)"
            );
        }

        @Test
        @DisplayName("Should download certificate successfully for PEM format")
        void shouldDownloadCertificateSuccessfullyForPEMFormat() {
            // Given
            String serialNumber = "1234567890";
            String format = "PEM";
            String password = null; // Not needed for PEM
            User requester = createUser(Role.ADMIN);
            Certificate certificate = createCertificate(CertificateType.END_ENTITY, CertificateStatus.VALID);

            // When & Then
            assertThrows(
                UnsupportedOperationException.class,
                () -> certificateService.downloadCertificate(serialNumber, format, password, requester),
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

    private CreateRootCertificateDTO createRootCertificateDTO() {
        CreateRootCertificateDTO dto = new CreateRootCertificateDTO();
        dto.setSubjectCN("Root CA");
        dto.setSubjectO("Test Organization");
        dto.setSubjectOU("IT Department");
        dto.setSubjectL("Test City");
        dto.setSubjectST("Test State");
        dto.setSubjectC("US");
        dto.setSubjectE("ca@example.com");
        dto.setValidityDays(3650);
        dto.setKeySize(4096);
        dto.setKeyUsage(Arrays.asList("digitalSignature", "keyCertSign", "cRLSign"));
        dto.setBasicConstraints(new CreateRootCertificateDTO.BasicConstraintsDTO(true, null));
        return dto;
    }

    private CreateIntermediateCertificateDTO createIntermediateCertificateDTO() {
        CreateIntermediateCertificateDTO dto = new CreateIntermediateCertificateDTO();
        dto.setIssuerCertificateId(1L);
        dto.setSubjectCN("Intermediate CA");
        dto.setSubjectO("Test Organization");
        dto.setSubjectOU("IT Department");
        dto.setSubjectL("Test City");
        dto.setSubjectST("Test State");
        dto.setSubjectC("US");
        dto.setSubjectE("intermediate@example.com");
        dto.setValidityDays(1825);
        dto.setKeySize(2048);
        dto.setKeyUsage(Arrays.asList("digitalSignature", "keyCertSign", "cRLSign"));
        dto.setBasicConstraints(new CreateIntermediateCertificateDTO.BasicConstraintsDTO(true, 0));
        return dto;
    }

    private CreateEndEntityCertificateDTO createEndEntityCertificateDTO() {
        CreateEndEntityCertificateDTO dto = new CreateEndEntityCertificateDTO();
        dto.setIssuerCertificateId(1L);
        dto.setSubjectCN("Test Certificate");
        dto.setSubjectO("Test Organization");
        dto.setSubjectOU("Test OU");
        dto.setSubjectL("Test City");
        dto.setSubjectST("Test State");
        dto.setSubjectC("US");
        dto.setSubjectE("test@example.com");
        dto.setValidityDays(365);
        dto.setKeySize(2048);
        dto.setKeyUsage(Arrays.asList("digitalSignature", "keyEncipherment"));
        dto.setExtendedKeyUsage(Arrays.asList("serverAuth", "clientAuth"));
        dto.setSubjectAlternativeNames(Arrays.asList("test.example.com", "192.168.1.1"));
        return dto;
    }

    private RevokeCertificateDTO createRevokeCertificateDTO() {
        RevokeCertificateDTO dto = new RevokeCertificateDTO();
        dto.setReason("keyCompromise");
        return dto;
    }
}
