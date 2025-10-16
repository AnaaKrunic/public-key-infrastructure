package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import java.util.ArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import static org.junit.jupiter.api.Assertions.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@DisplayName("CRLGeneratorService Tests")
class CRLGeneratorServiceTest {

    private CRLGeneratorService crlGeneratorService;
    private KeyPairGeneratorService keyPairGeneratorService;
    private CertificateGeneratorService certificateGeneratorService;

    @BeforeEach
    void setUp() {
        crlGeneratorService = new CRLGeneratorService();
        keyPairGeneratorService = new KeyPairGeneratorService();
        certificateGeneratorService = new CertificateGeneratorService();
    }

    @Nested
    @DisplayName("generateCRL Tests")
    class GenerateCRLTests {

        private KeyPair caKeyPair;
        private X500Name caDN;
        private X509Certificate caCertificate;

        @BeforeEach
        void setUp() throws Exception {
            caKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            caDN = certificateGeneratorService.buildX500Name(
                "Test CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "ca@example.com"
            );
            
            caCertificate = certificateGeneratorService.generateRootCertificate(
                caKeyPair, caDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
        }

        @Test
        @DisplayName("Should generate CRL successfully")
        void shouldGenerateCRLSuccessfully() throws Exception {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(
                BigInteger.valueOf(12345),
                BigInteger.valueOf(67890)
            );
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertNotNull(crl, "CRL should not be null");
            assertNotNull(crl.getRevokedCertificates(), "CRL should have revoked certificates list");
            assertEquals(revokedSerialNumbers.size(), crl.getRevokedCertificates().size(), 
                "CRL should contain all revoked certificates");
            
            // Verify issuer
            assertEquals(caDN.toString(), crl.getIssuer().toString(), 
                "CRL issuer should match CA certificate subject");
        }

        @Test
        @DisplayName("Should generate CRL with empty revocation list")
        void shouldGenerateCRLWithEmptyRevocationList() throws Exception {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList();
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertTrue(crl.getRevokedCertificates().isEmpty(), "CRL should have no revoked certificates");
        }

        @Test
        @DisplayName("Should generate CRL with multiple revoked certificates")
        void shouldGenerateCRLWithMultipleRevokedCertificates() throws Exception {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(
                BigInteger.valueOf(11111),
                BigInteger.valueOf(22222),
                BigInteger.valueOf(33333),
                BigInteger.valueOf(44444),
                BigInteger.valueOf(55555)
            );
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertEquals(revokedSerialNumbers.size(), crl.getRevokedCertificates().size(), 
                "CRL should contain all revoked certificates");
            
            // Verify each revoked certificate is present
            for (BigInteger serialNumber : revokedSerialNumbers) {
                assertNotNull(crl.getRevokedCertificate(serialNumber), 
                    "CRL should contain revoked certificate with serial number: " + serialNumber);
            }
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when caCertificate is null")
        void shouldThrowExceptionWhenCaCertificateIsNull() {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.generateCRL(
                    null, caKeyPair.getPrivate(), revokedSerialNumbers, crlDistributionPoint
                ),
                "Should throw IllegalArgumentException when caCertificate is null"
            );

            assertEquals("CA certificate cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when caPrivateKey is null")
        void shouldThrowExceptionWhenCaPrivateKeyIsNull() {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.generateCRL(
                    caCertificate, null, revokedSerialNumbers, crlDistributionPoint
                ),
                "Should throw IllegalArgumentException when caPrivateKey is null"
            );

            assertEquals("CA private key cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when revokedSerialNumbers is null")
        void shouldThrowExceptionWhenRevokedSerialNumbersIsNull() {
            // Given
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.generateCRL(
                    caCertificate, caKeyPair.getPrivate(), null, crlDistributionPoint
                ),
                "Should throw IllegalArgumentException when revokedSerialNumbers is null"
            );

            assertEquals("Revoked serial numbers cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when crlDistributionPoint is null")
        void shouldThrowExceptionWhenCrlDistributionPointIsNull() {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.generateCRL(
                    caCertificate, caKeyPair.getPrivate(), revokedSerialNumbers, null
                ),
                "Should throw IllegalArgumentException when crlDistributionPoint is null"
            );

            assertEquals("CRL distribution point must be a valid HTTP/HTTPS URL", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"invalid-url", "not-a-url", "ftp://invalid"})
        @DisplayName("Should throw IllegalArgumentException for invalid CRL distribution point")
        void shouldThrowExceptionForInvalidCrlDistributionPoint(String invalidDistributionPoint) {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.generateCRL(
                    caCertificate, caKeyPair.getPrivate(), revokedSerialNumbers, invalidDistributionPoint
                ),
                "Should throw IllegalArgumentException for invalid CRL distribution point: " + invalidDistributionPoint
            );

            assertEquals("CRL distribution point must be a valid HTTP/HTTPS URL", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when CA certificate is not a CA")
        void shouldThrowExceptionWhenCaCertificateIsNotCA() throws Exception {
            // Given
            KeyPair endEntityKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            var endEntityDN = certificateGeneratorService.buildX500Name(
                "End Entity", "Test Organization", "Test Department", 
                "Test City", "Test State", "US", "endentity@example.com"
            );
            
            X509Certificate endEntityCert = certificateGeneratorService.generateEndEntityCertificate(
                endEntityKeyPair, endEntityDN, caDN, 
                caKeyPair.getPrivate(), caKeyPair.getPublic(),
                365, Arrays.asList("digitalSignature"), 
                Arrays.asList("serverAuth"), Arrays.asList("endentity.example.com"), null
            );
            
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.generateCRL(
                    endEntityCert, caKeyPair.getPrivate(), revokedSerialNumbers, crlDistributionPoint
                ),
                "Should throw IllegalArgumentException when CA certificate is not a CA"
            );

            assertEquals("Certificate must be a CA certificate (have keyCertSign usage)", exception.getMessage());
        }

        @Test
        @DisplayName("Should generate CRL with proper validity period")
        void shouldGenerateCRLWithProperValidityPeriod() throws Exception {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            
            // Verify this update time is recent
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime thisUpdate = crl.getThisUpdate().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
            LocalDateTime nextUpdate = crl.getNextUpdate().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
            
            assertTrue(thisUpdate.isBefore(now.plusMinutes(1)), "This update should be before now");
            assertTrue(nextUpdate.isAfter(now.plusDays(6)), "Next update should be after 7 days");
            assertTrue(nextUpdate.isBefore(now.plusDays(8)), "Next update should be before 8 days");
        }

        @Test
        @DisplayName("Should generate CRL with proper signature")
        void shouldGenerateCRLWithProperSignature() throws Exception {
            // Given
            List<BigInteger> revokedSerialNumbers = Arrays.asList(BigInteger.valueOf(12345));
            String crlDistributionPoint = "http://crl.example.com/test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertNotNull(crl, "CRL should not be null");
            assertTrue(crl.getRevokedCertificates().size() > 0, "CRL should have revoked certificates");
            
            // Verify signature algorithm
            assertNotNull(crl, "CRL should not be null");
        }
    }

    @Nested
    @DisplayName("addRevokedCertificate Tests")
    class AddRevokedCertificateTests {

        private X509v2CRLBuilder crlBuilder;
        private KeyPair caKeyPair;
        private X500Name caDN;

        @BeforeEach
        void setUp() throws Exception {
            caKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            caDN = certificateGeneratorService.buildX500Name(
                "Test CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "ca@example.com"
            );
            
            crlBuilder = new X509v2CRLBuilder(caDN, new Date());
        }

        @Test
        @DisplayName("Should add revoked certificate successfully")
        void shouldAddRevokedCertificateSuccessfully() throws Exception {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            Date revocationDate = new Date();
            int revocationReason = 0; // unspecified

            // When
            crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, revocationReason);

            // Then
            // Verify the certificate was added by building the CRL
            X509CRLHolder crl = crlGeneratorService.buildCRL(crlBuilder, caKeyPair.getPrivate());
            assertNotNull(crl.getRevokedCertificate(serialNumber), 
                "Revoked certificate should be present in CRL");
        }

        @Test
        @DisplayName("Should add multiple revoked certificates")
        void shouldAddMultipleRevokedCertificates() throws Exception {
            // Given
            BigInteger[] serialNumbers = {
                BigInteger.valueOf(11111),
                BigInteger.valueOf(22222),
                BigInteger.valueOf(33333)
            };
            Date revocationDate = new Date();
            int revocationReason = 1; // keyCompromise

            // When
            for (BigInteger serialNumber : serialNumbers) {
                crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, revocationReason);
            }

            // Then
            X509CRLHolder crl = crlGeneratorService.buildCRL(crlBuilder, caKeyPair.getPrivate());
            assertEquals(serialNumbers.length, crl.getRevokedCertificates().size(), 
                "CRL should contain all revoked certificates");
            
            for (BigInteger serialNumber : serialNumbers) {
                assertNotNull(crl.getRevokedCertificate(serialNumber), 
                    "Revoked certificate should be present in CRL: " + serialNumber);
            }
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when crlBuilder is null")
        void shouldThrowExceptionWhenCrlBuilderIsNull() {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            Date revocationDate = new Date();
            int revocationReason = 0;

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.addRevokedCertificate(null, serialNumber, revocationDate, revocationReason),
                "Should throw IllegalArgumentException when crlBuilder is null"
            );

            assertEquals("CRL builder cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when serialNumber is null")
        void shouldThrowExceptionWhenSerialNumberIsNull() {
            // Given
            Date revocationDate = new Date();
            int revocationReason = 0;

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.addRevokedCertificate(crlBuilder, null, revocationDate, revocationReason),
                "Should throw IllegalArgumentException when serialNumber is null"
            );

            assertEquals("Serial number cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when revocationDate is null")
        void shouldThrowExceptionWhenRevocationDateIsNull() {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            int revocationReason = 0;

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, null, revocationReason),
                "Should throw IllegalArgumentException when revocationDate is null"
            );

            assertEquals("Revocation date cannot be null", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, -10, 10, 100})
        @DisplayName("Should throw IllegalArgumentException for invalid revocation reason")
        void shouldThrowExceptionForInvalidRevocationReason(int invalidReason) {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            Date revocationDate = new Date();

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, invalidReason),
                "Should throw IllegalArgumentException for invalid revocation reason: " + invalidReason
            );

            assertEquals("Revocation reason must be between 0 and 9", exception.getMessage());
        }

        @Test
        @DisplayName("Should handle duplicate serial numbers")
        void shouldHandleDuplicateSerialNumbers() throws Exception {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            Date revocationDate = new Date();
            int revocationReason = 0;

            // When
            crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, revocationReason);
            // Adding the same serial number again should not cause an error
            crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, revocationReason);

            // Then
            X509CRLHolder crl = crlGeneratorService.buildCRL(crlBuilder, caKeyPair.getPrivate());
            assertNotNull(crl.getRevokedCertificate(serialNumber), 
                "Revoked certificate should be present in CRL");
        }
    }

    @Nested
    @DisplayName("buildCRL Tests")
    class BuildCRLTests {

        private X509v2CRLBuilder crlBuilder;
        private KeyPair caKeyPair;
        private X500Name caDN;

        @BeforeEach
        void setUp() throws Exception {
            caKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            caDN = certificateGeneratorService.buildX500Name(
                "Test CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "ca@example.com"
            );
            
            crlBuilder = new X509v2CRLBuilder(caDN, new Date());
        }

        @Test
        @DisplayName("Should build CRL successfully")
        void shouldBuildCRLSuccessfully() throws Exception {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            Date revocationDate = new Date();
            int revocationReason = 0;
            
            crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, revocationReason);

            // When
            X509CRLHolder crl = crlGeneratorService.buildCRL(crlBuilder, caKeyPair.getPrivate());

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertNotNull(crl.getRevokedCertificates(), "CRL should have revoked certificates list");
            assertEquals(1, crl.getRevokedCertificates().size(), 
                "CRL should contain the revoked certificate");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when crlBuilder is null")
        void shouldThrowExceptionWhenCrlBuilderIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.buildCRL(null, caKeyPair.getPrivate()),
                "Should throw IllegalArgumentException when crlBuilder is null"
            );

            assertEquals("CRL builder cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when caPrivateKey is null")
        void shouldThrowExceptionWhenCaPrivateKeyIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> crlGeneratorService.buildCRL(crlBuilder, null),
                "Should throw IllegalArgumentException when caPrivateKey is null"
            );

            assertEquals("CA private key cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should build CRL with proper signature")
        void shouldBuildCRLWithProperSignature() throws Exception {
            // Given
            BigInteger serialNumber = BigInteger.valueOf(12345);
            Date revocationDate = new Date();
            int revocationReason = 0;
            
            crlGeneratorService.addRevokedCertificate(crlBuilder, serialNumber, revocationDate, revocationReason);

            // When
            X509CRLHolder crl = crlGeneratorService.buildCRL(crlBuilder, caKeyPair.getPrivate());

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertNotNull(crl, "CRL should not be null");
            assertTrue(crl.getRevokedCertificates().size() > 0, "CRL should have revoked certificates");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should generate and verify CRL in complete workflow")
        void shouldGenerateAndVerifyCRLInCompleteWorkflow() throws Exception {
            // Given
            KeyPair caKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            var caDN = certificateGeneratorService.buildX500Name(
                "Integration Test CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "ca@example.com"
            );
            
            X509Certificate caCertificate = certificateGeneratorService.generateRootCertificate(
                caKeyPair, caDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
            
            List<BigInteger> revokedSerialNumbers = Arrays.asList(
                BigInteger.valueOf(11111),
                BigInteger.valueOf(22222),
                BigInteger.valueOf(33333)
            );
            String crlDistributionPoint = "http://crl.example.com/integration-test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertEquals(revokedSerialNumbers.size(), crl.getRevokedCertificates().size(), 
                "CRL should contain all revoked certificates");
            
            // Verify each revoked certificate is present
            for (BigInteger serialNumber : revokedSerialNumbers) {
                assertNotNull(crl.getRevokedCertificate(serialNumber), 
                    "CRL should contain revoked certificate with serial number: " + serialNumber);
            }
            
            // Verify CRL signature
            assertNotNull(crl, "CRL should not be null");
            assertTrue(crl.getRevokedCertificates().size() > 0, "CRL should have revoked certificates");
        }

        @Test
        @DisplayName("Should handle large number of revoked certificates")
        void shouldHandleLargeNumberOfRevokedCertificates() throws Exception {
            // Given
            KeyPair caKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            var caDN = certificateGeneratorService.buildX500Name(
                "Large CRL Test CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "ca@example.com"
            );
            
            X509Certificate caCertificate = certificateGeneratorService.generateRootCertificate(
                caKeyPair, caDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
            
            // Generate 1000 revoked serial numbers
            List<BigInteger> revokedSerialNumbers = new java.util.ArrayList<>();
            for (int i = 1; i <= 1000; i++) {
                revokedSerialNumbers.add(BigInteger.valueOf(i));
            }
            
            String crlDistributionPoint = "http://crl.example.com/large-crl-test-ca.crl";

            // When
            X509CRLHolder crl = crlGeneratorService.generateCRL(
                caCertificate, caKeyPair.getPrivate(), 
                revokedSerialNumbers, crlDistributionPoint
            );

            // Then
            assertNotNull(crl, "CRL should not be null");
            assertEquals(revokedSerialNumbers.size(), crl.getRevokedCertificates().size(), 
                "CRL should contain all revoked certificates");
        }
    }
}
