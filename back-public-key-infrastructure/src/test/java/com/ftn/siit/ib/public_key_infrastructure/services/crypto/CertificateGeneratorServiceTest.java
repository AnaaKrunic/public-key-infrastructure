package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@DisplayName("CertificateGeneratorService Tests")
class CertificateGeneratorServiceTest {

    private CertificateGeneratorService certificateGeneratorService;
    private KeyPairGeneratorService keyPairGeneratorService;

    @BeforeEach
    void setUp() {
        certificateGeneratorService = new CertificateGeneratorService();
        keyPairGeneratorService = new KeyPairGeneratorService();
    }

    @Nested
    @DisplayName("buildX500Name Tests")
    class BuildX500NameTests {

        @Test
        @DisplayName("Should build X500Name with all components")
        void shouldBuildX500NameWithAllComponents() {
            // Given
            String cn = "Test Certificate";
            String o = "Test Organization";
            String ou = "Test Department";
            String l = "Test City";
            String st = "Test State";
            String c = "US";
            String e = "test@example.com";

            // When
            X500Name x500Name = certificateGeneratorService.buildX500Name(cn, o, ou, l, st, c, e);

            // Then
            assertNotNull(x500Name, "X500Name should not be null");
            String dnString = x500Name.toString();
            assertTrue(dnString.contains("CN=Test Certificate"), "Should contain CN");
            assertTrue(dnString.contains("O=Test Organization"), "Should contain O");
            assertTrue(dnString.contains("OU=Test Department"), "Should contain OU");
            assertTrue(dnString.contains("L=Test City"), "Should contain L");
            assertTrue(dnString.contains("ST=Test State"), "Should contain ST");
            assertTrue(dnString.contains("C=US"), "Should contain C");
            assertTrue(dnString.contains("E=test@example.com"), "Should contain E");
        }

        @Test
        @DisplayName("Should build X500Name with only CN")
        void shouldBuildX500NameWithOnlyCN() {
            // Given
            String cn = "Test Certificate";

            // When
            X500Name x500Name = certificateGeneratorService.buildX500Name(cn, null, null, null, null, null, null);

            // Then
            assertNotNull(x500Name, "X500Name should not be null");
            String dnString = x500Name.toString();
            assertEquals("CN=Test Certificate", dnString, "Should contain only CN");
        }

        @Test
        @DisplayName("Should handle special characters in DN components")
        void shouldHandleSpecialCharactersInDNComponents() {
            // Given
            String cn = "Test, Inc.";
            String o = "Test \"Corp\"";
            String ou = "Test+Department";

            // When
            X500Name x500Name = certificateGeneratorService.buildX500Name(cn, o, ou, null, null, null, null);

            // Then
            assertNotNull(x500Name, "X500Name should not be null");
            String dnString = x500Name.toString();
            assertTrue(dnString.contains("CN=Test\\, Inc."), "Should escape comma in CN");
            assertTrue(dnString.contains("O=Test \\\"Corp\\\""), "Should escape quotes in O");
            assertTrue(dnString.contains("OU=Test\\+Department"), "Should escape plus in OU");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when CN is null")
        void shouldThrowExceptionWhenCNIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildX500Name(null, "Org", null, null, null, "US", null),
                "Should throw IllegalArgumentException when CN is null"
            );

            assertEquals("Common Name (CN) is required", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when CN is empty")
        void shouldThrowExceptionWhenCNIsEmpty() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildX500Name("", "Org", null, null, null, "US", null),
                "Should throw IllegalArgumentException when CN is empty"
            );

            assertEquals("Common Name (CN) is required", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when CN is whitespace only")
        void shouldThrowExceptionWhenCNIsWhitespaceOnly() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildX500Name("   ", "Org", null, null, null, "US", null),
                "Should throw IllegalArgumentException when CN is whitespace only"
            );

            assertEquals("Common Name (CN) is required", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"us", "USA", "U", "123", "XX"})
        @DisplayName("Should throw IllegalArgumentException for invalid country codes")
        void shouldThrowExceptionForInvalidCountryCodes(String invalidCountry) {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildX500Name("Test", "Org", null, null, null, invalidCountry, null),
                "Should throw IllegalArgumentException for invalid country: " + invalidCountry
            );

            assertEquals("Country code must be 2-letter uppercase ISO 3166-1 code", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"invalid-email", "test@", "@example.com", "test.example.com"})
        @DisplayName("Should throw IllegalArgumentException for invalid email formats")
        void shouldThrowExceptionForInvalidEmailFormats(String invalidEmail) {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildX500Name("Test", "Org", null, null, null, "US", invalidEmail),
                "Should throw IllegalArgumentException for invalid email: " + invalidEmail
            );

            assertEquals("Invalid email address format", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"test@example.com", "user.name@domain.co.uk", "test+tag@example.org"})
        @DisplayName("Should accept valid email formats")
        void shouldAcceptValidEmailFormats(String validEmail) {
            // When
            X500Name x500Name = certificateGeneratorService.buildX500Name("Test", "Org", null, null, null, "US", validEmail);

            // Then
            assertNotNull(x500Name, "X500Name should be created for valid email: " + validEmail);
            String dnString = x500Name.toString();
            assertTrue(dnString.contains("E=" + validEmail), "Should contain valid email");
        }
    }

    @Nested
    @DisplayName("generateSerialNumber Tests")
    class GenerateSerialNumberTests {

        @Test
        @DisplayName("Should generate positive serial number")
        void shouldGeneratePositiveSerialNumber() {
            // When
            BigInteger serialNumber = certificateGeneratorService.generateSerialNumber();

            // Then
            assertNotNull(serialNumber, "Serial number should not be null");
            assertTrue(serialNumber.compareTo(BigInteger.ZERO) > 0, "Serial number should be positive");
        }

        @Test
        @DisplayName("Should generate different serial numbers for multiple calls")
        void shouldGenerateDifferentSerialNumbers() {
            // When
            BigInteger serial1 = certificateGeneratorService.generateSerialNumber();
            BigInteger serial2 = certificateGeneratorService.generateSerialNumber();
            BigInteger serial3 = certificateGeneratorService.generateSerialNumber();

            // Then
            assertNotEquals(serial1, serial2, "Serial numbers should be different");
            assertNotEquals(serial1, serial3, "Serial numbers should be different");
            assertNotEquals(serial2, serial3, "Serial numbers should be different");
        }

        @Test
        @DisplayName("Should generate 128-bit serial number")
        void shouldGenerate128BitSerialNumber() {
            // When
            BigInteger serialNumber = certificateGeneratorService.generateSerialNumber();

            // Then
            assertTrue(serialNumber.bitLength() <= 128, "Serial number should be 128 bits or less");
            assertTrue(serialNumber.bitLength() >= 64, "Serial number should be at least 64 bits");
        }

        @Test
        @DisplayName("Should generate cryptographically random serial numbers")
        void shouldGenerateCryptographicallyRandomSerialNumbers() {
            // When
            Set<BigInteger> serialNumbers = new HashSet<>();
            for (int i = 0; i < 1000; i++) {
                serialNumbers.add(certificateGeneratorService.generateSerialNumber());
            }

            // Then
            assertEquals(1000, serialNumbers.size(), "All serial numbers should be unique");
        }
    }

    @Nested
    @DisplayName("generateRootCertificate Tests")
    class GenerateRootCertificateTests {

        private KeyPair keyPair;
        private X500Name subjectDN;

        @BeforeEach
        void setUp() {
            keyPair = keyPairGeneratorService.generateKeyPair(4096);
            subjectDN = certificateGeneratorService.buildX500Name(
                "Root CA", "Test Organization", "IT Security", 
                "San Francisco", "California", "US", "admin@example.com"
            );
        }

        @Test
        @DisplayName("Should generate valid root certificate")
        void shouldGenerateValidRootCertificate() throws Exception {
            // Given
            int validityDays = 3650;
            List<String> keyUsage = Arrays.asList("keyCertSign", "cRLSign");
            Integer pathLength = 2;

            // When
            X509Certificate certificate = certificateGeneratorService.generateRootCertificate(
                keyPair, subjectDN, validityDays, keyUsage, pathLength
            );

            // Then
            assertNotNull(certificate, "Certificate should not be null");
            assertEquals("X.509", certificate.getType(), "Certificate type should be X.509");
            assertEquals(3, certificate.getVersion(), "Certificate version should be 3");
            assertEquals("SHA256withRSA", certificate.getSigAlgName(), "Signature algorithm should be SHA256withRSA");
            
            // Verify subject and issuer are the same (self-signed)
            assertEquals(certificate.getSubjectDN().toString(), certificate.getIssuerDN().toString(),
                "Subject and issuer should be the same for root certificate");
            
            // Verify validity period
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime notBefore = certificate.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
            LocalDateTime notAfter = certificate.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
            
            assertTrue(notBefore.isBefore(now.plusMinutes(1)), "NotBefore should be before now");
            assertTrue(notAfter.isAfter(now.plusDays(validityDays - 1)), "NotAfter should be after validity period");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyPair is null")
        void shouldThrowExceptionWhenKeyPairIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateRootCertificate(
                    null, subjectDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
                ),
                "Should throw IllegalArgumentException when keyPair is null"
            );

            assertEquals("KeyPair cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when subjectDN is null")
        void shouldThrowExceptionWhenSubjectDNIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateRootCertificate(
                    keyPair, null, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
                ),
                "Should throw IllegalArgumentException when subjectDN is null"
            );

            assertEquals("Subject DN cannot be null", exception.getMessage());
        }

        @ParameterizedTest
        @CsvSource({
            "364, 365, 7300",
            "7301, 365, 7300",
            "0, 365, 7300",
            "-1, 365, 7300"
        })
        @DisplayName("Should throw IllegalArgumentException for invalid validity days")
        void shouldThrowExceptionForInvalidValidityDays(int validityDays, int minDays, int maxDays) {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateRootCertificate(
                    keyPair, subjectDN, validityDays, Arrays.asList("keyCertSign", "cRLSign"), 2
                ),
                "Should throw IllegalArgumentException for validity days: " + validityDays
            );

            assertEquals("Validity must be between 365 and 7300 days", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyUsage missing keyCertSign")
        void shouldThrowExceptionWhenKeyUsageMissingKeyCertSign() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateRootCertificate(
                    keyPair, subjectDN, 3650, Arrays.asList("cRLSign"), 2
                ),
                "Should throw IllegalArgumentException when keyUsage missing keyCertSign"
            );

            assertEquals("Root CA must have keyCertSign usage", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyUsage missing cRLSign")
        void shouldThrowExceptionWhenKeyUsageMissingCRLSign() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateRootCertificate(
                    keyPair, subjectDN, 3650, Arrays.asList("keyCertSign"), 2
                ),
                "Should throw IllegalArgumentException when keyUsage missing cRLSign"
            );

            assertEquals("Root CA must have cRLSign usage", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for negative path length")
        void shouldThrowExceptionForNegativePathLength() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateRootCertificate(
                    keyPair, subjectDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), -1
                ),
                "Should throw IllegalArgumentException for negative path length"
            );

            assertEquals("Path length cannot be negative", exception.getMessage());
        }

        @Test
        @DisplayName("Should generate certificate with correct extensions")
        void shouldGenerateCertificateWithCorrectExtensions() throws Exception {
            // Given
            List<String> keyUsage = Arrays.asList("keyCertSign", "cRLSign");
            Integer pathLength = 2;

            // When
            X509Certificate certificate = certificateGeneratorService.generateRootCertificate(
                keyPair, subjectDN, 3650, keyUsage, pathLength
            );

            // Then
            // Verify Basic Constraints extension
            boolean[] keyUsageArray = certificate.getKeyUsage();
            assertTrue(keyUsageArray[5], "Key usage should include keyCertSign");
            assertTrue(keyUsageArray[6], "Key usage should include cRLSign");
            
            // Verify certificate is self-signed
            certificate.verify(certificate.getPublicKey());
        }
    }

    @Nested
    @DisplayName("generateIntermediateCertificate Tests")
    class GenerateIntermediateCertificateTests {

        private KeyPair rootKeyPair;
        private KeyPair intermediateKeyPair;
        private X500Name rootDN;
        private X500Name intermediateDN;

        @BeforeEach
        void setUp() {
            rootKeyPair = keyPairGeneratorService.generateKeyPair(4096);
            intermediateKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            
            rootDN = certificateGeneratorService.buildX500Name(
                "Root CA", "Test Organization", "IT Security", 
                "San Francisco", "California", "US", "root@example.com"
            );
            
            intermediateDN = certificateGeneratorService.buildX500Name(
                "Intermediate CA", "Test Organization", "Engineering", 
                "San Francisco", "California", "US", "intermediate@example.com"
            );
        }

        @Test
        @DisplayName("Should generate valid intermediate certificate")
        void shouldGenerateValidIntermediateCertificate() throws Exception {
            // Given
            int validityDays = 1825;
            List<String> keyUsage = Arrays.asList("keyCertSign", "cRLSign");
            Integer pathLength = 1;

            // When
            X509Certificate certificate = certificateGeneratorService.generateIntermediateCertificate(
                intermediateKeyPair, intermediateDN, rootDN, 
                rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
                validityDays, keyUsage, pathLength
            );

            // Then
            assertNotNull(certificate, "Certificate should not be null");
            assertEquals("X.509", certificate.getType(), "Certificate type should be X.509");
            assertEquals(3, certificate.getVersion(), "Certificate version should be 3");
            assertEquals("SHA256withRSA", certificate.getSigAlgName(), "Signature algorithm should be SHA256withRSA");
            
            // Verify subject and issuer are different
            assertNotEquals(certificate.getSubjectDN().toString(), certificate.getIssuerDN().toString(),
                "Subject and issuer should be different for intermediate certificate");
            
            // Verify signature
            certificate.verify(rootKeyPair.getPublic());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when subjectDN equals issuerDN")
        void shouldThrowExceptionWhenSubjectDNEqualsIssuerDN() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateIntermediateCertificate(
                    intermediateKeyPair, rootDN, rootDN, 
                    rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
                    1825, Arrays.asList("keyCertSign", "cRLSign"), 1
                ),
                "Should throw IllegalArgumentException when subjectDN equals issuerDN"
            );

            assertEquals("Intermediate certificate cannot be self-signed", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for invalid validity days")
        void shouldThrowExceptionForInvalidValidityDays() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateIntermediateCertificate(
                    intermediateKeyPair, intermediateDN, rootDN, 
                    rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
                    364, Arrays.asList("keyCertSign", "cRLSign"), 1
                ),
                "Should throw IllegalArgumentException for invalid validity days"
            );

            assertEquals("Validity must be between 365 and 3650 days", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("generateEndEntityCertificate Tests")
    class GenerateEndEntityCertificateTests {

        private KeyPair caKeyPair;
        private KeyPair endEntityKeyPair;
        private X500Name caDN;
        private X500Name endEntityDN;

        @BeforeEach
        void setUp() {
            caKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            endEntityKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            
            caDN = certificateGeneratorService.buildX500Name(
                "Intermediate CA", "Test Organization", "Engineering", 
                "San Francisco", "California", "US", "ca@example.com"
            );
            
            endEntityDN = certificateGeneratorService.buildX500Name(
                "server.example.com", "Test Organization", "Engineering", 
                "San Francisco", "California", "US", "admin@server.example.com"
            );
        }

        @Test
        @DisplayName("Should generate valid end-entity certificate")
        void shouldGenerateValidEndEntityCertificate() throws Exception {
            // Given
            int validityDays = 365;
            List<String> keyUsage = Arrays.asList("digitalSignature", "keyEncipherment");
            List<String> extendedKeyUsage = Arrays.asList("serverAuth", "clientAuth");
            List<String> subjectAlternativeNames = Arrays.asList("server.example.com", "www.example.com");

            // When
            X509Certificate certificate = certificateGeneratorService.generateEndEntityCertificate(
                endEntityKeyPair, endEntityDN, caDN, 
                caKeyPair.getPrivate(), caKeyPair.getPublic(),
                validityDays, keyUsage, extendedKeyUsage, subjectAlternativeNames, "http://crl.example.com"
            );

            // Then
            assertNotNull(certificate, "Certificate should not be null");
            assertEquals("X.509", certificate.getType(), "Certificate type should be X.509");
            assertEquals(3, certificate.getVersion(), "Certificate version should be 3");
            assertEquals("SHA256withRSA", certificate.getSigAlgName(), "Signature algorithm should be SHA256withRSA");
            
            // Verify signature
            certificate.verify(caKeyPair.getPublic());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyUsage contains keyCertSign")
        void shouldThrowExceptionWhenKeyUsageContainsKeyCertSign() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateEndEntityCertificate(
                    endEntityKeyPair, endEntityDN, caDN, 
                    caKeyPair.getPrivate(), caKeyPair.getPublic(),
                    365, Arrays.asList("digitalSignature", "keyCertSign"), 
                    Arrays.asList("serverAuth"), Arrays.asList("server.example.com"), null
                ),
                "Should throw IllegalArgumentException when keyUsage contains keyCertSign"
            );

            assertEquals("End-entity certificate cannot have keyCertSign usage", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyUsage contains cRLSign")
        void shouldThrowExceptionWhenKeyUsageContainsCRLSign() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateEndEntityCertificate(
                    endEntityKeyPair, endEntityDN, caDN, 
                    caKeyPair.getPrivate(), caKeyPair.getPublic(),
                    365, Arrays.asList("digitalSignature", "cRLSign"), 
                    Arrays.asList("serverAuth"), Arrays.asList("server.example.com"), null
                ),
                "Should throw IllegalArgumentException when keyUsage contains cRLSign"
            );

            assertEquals("End-entity certificate cannot have cRLSign usage", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for invalid validity days")
        void shouldThrowExceptionForInvalidValidityDays() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.generateEndEntityCertificate(
                    endEntityKeyPair, endEntityDN, caDN, 
                    caKeyPair.getPrivate(), caKeyPair.getPublic(),
                    366, Arrays.asList("digitalSignature"), 
                    Arrays.asList("serverAuth"), Arrays.asList("server.example.com"), null
                ),
                "Should throw IllegalArgumentException for invalid validity days"
            );

            assertEquals("Validity must be between 1 and 365 days", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("Helper Methods Tests")
    class HelperMethodsTests {

        @Test
        @DisplayName("buildKeyUsage should handle valid key usage strings")
        void buildKeyUsageShouldHandleValidKeyUsageStrings() {
            // Given
            List<String> keyUsageList = Arrays.asList("digitalSignature", "keyEncipherment", "keyCertSign");

            // When
            KeyUsage keyUsage = certificateGeneratorService.buildKeyUsage(keyUsageList);

            // Then
            assertNotNull(keyUsage, "KeyUsage should not be null");
            assertTrue(keyUsage.hasUsages(KeyUsage.digitalSignature), "Should have digitalSignature usage");
            assertTrue(keyUsage.hasUsages(KeyUsage.keyEncipherment), "Should have keyEncipherment usage");
            assertTrue(keyUsage.hasUsages(KeyUsage.keyCertSign), "Should have keyCertSign usage");
        }

        @Test
        @DisplayName("buildKeyUsage should throw IllegalArgumentException for empty list")
        void buildKeyUsageShouldThrowExceptionForEmptyList() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildKeyUsage(Collections.emptyList()),
                "Should throw IllegalArgumentException for empty list"
            );

            assertEquals("Key usage list cannot be empty", exception.getMessage());
        }

        @Test
        @DisplayName("buildKeyUsage should throw IllegalArgumentException for invalid usage")
        void buildKeyUsageShouldThrowExceptionForInvalidUsage() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildKeyUsage(Arrays.asList("invalidUsage")),
                "Should throw IllegalArgumentException for invalid usage"
            );

            assertEquals("Invalid key usage: invalidUsage", exception.getMessage());
        }

        @Test
        @DisplayName("buildExtendedKeyUsage should handle valid EKU strings")
        void buildExtendedKeyUsageShouldHandleValidEKUStrings() {
            // Given
            List<String> ekuList = Arrays.asList("serverAuth", "clientAuth");

            // When
            ExtendedKeyUsage eku = certificateGeneratorService.buildExtendedKeyUsage(ekuList);

            // Then
            assertNotNull(eku, "ExtendedKeyUsage should not be null");
            assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth), "Should have serverAuth purpose");
            assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth), "Should have clientAuth purpose");
        }

        @Test
        @DisplayName("buildExtendedKeyUsage should return null for empty list")
        void buildExtendedKeyUsageShouldReturnNullForEmptyList() {
            // When
            ExtendedKeyUsage eku = certificateGeneratorService.buildExtendedKeyUsage(Collections.emptyList());

            // Then
            assertNull(eku, "ExtendedKeyUsage should be null for empty list");
        }

        @Test
        @DisplayName("buildExtendedKeyUsage should throw IllegalArgumentException for invalid EKU")
        void buildExtendedKeyUsageShouldThrowExceptionForInvalidEKU() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> certificateGeneratorService.buildExtendedKeyUsage(Arrays.asList("invalidEKU")),
                "Should throw IllegalArgumentException for invalid EKU"
            );

            assertEquals("Invalid extended key usage: invalidEKU", exception.getMessage());
        }
    }
}
