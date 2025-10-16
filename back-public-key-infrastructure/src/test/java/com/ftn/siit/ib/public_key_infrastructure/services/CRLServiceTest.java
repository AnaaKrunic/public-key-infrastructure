package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.entities.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;


import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CRLService Tests")
class CRLServiceTest {

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CRLGeneratorService crlGeneratorService;

    @Mock
    private EncryptionService encryptionService;

    private CRLService crlService;

    @BeforeEach
    void setUp() {
        crlService = new CRLService(
            certificateRepository,
            crlGeneratorService,
            encryptionService
        );
    }

    @Nested
    @DisplayName("generateCRL Tests")
    class GenerateCRLTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when CA certificate is null")
        void shouldThrowExceptionWhenCACertificateIsNull() {
            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> crlService.generateCRL(null),
                "Should throw IllegalArgumentException when CA certificate is null"
            );
        }

        @Test
        @DisplayName("Should generate CRL successfully")
        void shouldGenerateCRLSuccessfully() {
            // Given
            Certificate caCertificate = createCertificate();

            // When
            byte[] result = crlService.generateCRL(caCertificate);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.length > 0, "Result should not be empty");
            String resultString = new String(result);
            assertTrue(resultString.contains("X509 CRL"), "Result should contain CRL data");
        }
    }

    @Nested
    @DisplayName("getCRL Tests")
    class GetCRLTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when CA serial number is null")
        void shouldThrowExceptionWhenCASerialNumberIsNull() {
            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> crlService.getCRL(null),
                "Should throw IllegalArgumentException when CA serial number is null"
            );
        }

        @Test
        @DisplayName("Should get CRL successfully")
        void shouldGetCRLSuccessfully() {
            // Given
            String caSerialNumber = "12345";

            // When
            byte[] result = crlService.getCRL(caSerialNumber);

            // Then
            assertNotNull(result, "Result should not be null");
            assertTrue(result.length > 0, "Result should not be empty");
            String resultString = new String(result);
            assertTrue(resultString.contains("X509 CRL"), "Result should contain CRL data");
            assertTrue(resultString.contains(caSerialNumber), "Result should contain CA serial number");
        }
    }

    @Nested
    @DisplayName("updateCRL Tests")
    class UpdateCRLTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when CA certificate is null")
        void shouldThrowExceptionWhenCACertificateIsNull() {
            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> crlService.updateCRL(null),
                "Should throw IllegalArgumentException when CA certificate is null"
            );
        }

        @Test
        @DisplayName("Should update CRL successfully")
        void shouldUpdateCRLSuccessfully() {
            // Given
            Certificate caCertificate = createCertificate();

            // When & Then
            assertDoesNotThrow(
                () -> crlService.updateCRL(caCertificate),
                "Should not throw any exception"
            );
        }
    }

    @Nested
    @DisplayName("checkRevocationStatus Tests")
    class CheckRevocationStatusTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificate serial number is null")
        void shouldThrowExceptionWhenSerialNumberIsNull() {
            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> crlService.checkRevocationStatus(null),
                "Should throw IllegalArgumentException when certificate serial number is null"
            );
        }

        @Test
        @DisplayName("Should check revocation status successfully")
        void shouldCheckRevocationStatusSuccessfully() {
            // Given
            String serialNumber = "12345";

            // When
            boolean result = crlService.checkRevocationStatus(serialNumber);

            // Then
            assertFalse(result, "Certificate should not be revoked (placeholder implementation)");
        }
    }

    // Helper methods
    private Certificate createCertificate() {
        Certificate certificate = new Certificate();
        certificate.setId(1L);
        certificate.setSerialNumber("12345");
        certificate.setSubjectCN("Test CA");
        certificate.setSubjectO("Test Organization");
        certificate.setSubjectC("US");
        certificate.setSubjectDN("CN=Test CA,O=Test Organization,C=US");
        certificate.setIssuerDN("CN=Test CA,O=Test Organization,C=US");
        certificate.setValidFrom(LocalDateTime.now().minusDays(365));
        certificate.setValidTo(LocalDateTime.now().plusDays(365));
        certificate.setCertificateType(CertificateType.ROOT);
        certificate.setStatus(CertificateStatus.VALID);
        certificate.setKeyUsage("keyCertSign,cRLSign");
        certificate.setCreatedAt(LocalDateTime.now());
        return certificate;
    }

}
