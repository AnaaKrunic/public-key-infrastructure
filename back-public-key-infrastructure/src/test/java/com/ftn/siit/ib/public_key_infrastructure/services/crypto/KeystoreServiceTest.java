package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

@DisplayName("KeystoreService Tests")
class KeystoreServiceTest {

    private KeystoreService keystoreService;
    private KeyPairGeneratorService keyPairGeneratorService;
    private CertificateGeneratorService certificateGeneratorService;

    @BeforeEach
    void setUp() {
        keystoreService = new KeystoreService();
        keyPairGeneratorService = new KeyPairGeneratorService();
        certificateGeneratorService = new CertificateGeneratorService();
    }

    @Nested
    @DisplayName("createPKCS12Keystore Tests")
    class CreatePKCS12KeystoreTests {

        private KeyPair keyPair;
        private X509Certificate certificate;
        private String keystorePassword;

        @BeforeEach
        void setUp() throws Exception {
            keyPair = keyPairGeneratorService.generateKeyPair(2048);
            keystorePassword = "testPassword123";
            
            // Create a self-signed certificate for testing
            var subjectDN = certificateGeneratorService.buildX500Name(
                "Test Certificate", "Test Organization", "Test Department", 
                "Test City", "Test State", "US", "test@example.com"
            );
            
            certificate = certificateGeneratorService.generateRootCertificate(
                keyPair, subjectDN, 365, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
        }

        @Test
        @DisplayName("Should create PKCS12 keystore successfully")
        void shouldCreatePKCS12KeystoreSuccessfully() throws Exception {
            // When
            byte[] keystoreData = keystoreService.createPKCS12Keystore(
                keyPair.getPrivate(), certificate, keystorePassword
            );

            // Then
            assertNotNull(keystoreData, "Keystore data should not be null");
            assertTrue(keystoreData.length > 0, "Keystore data should not be empty");
            
            // Verify it's a valid PKCS12 keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(keystoreData), keystorePassword.toCharArray());
            
            assertTrue(keystore.containsAlias("privatekey"), "Keystore should contain private key");
            assertTrue(keystore.containsAlias("certificate"), "Keystore should contain certificate");
        }

        @Test
        @DisplayName("Should create keystore with certificate chain")
        void shouldCreateKeystoreWithCertificateChain() throws Exception {
            // Given
            List<X509Certificate> certificateChain = Arrays.asList(certificate);

            // When
            byte[] keystoreData = keystoreService.createPKCS12Keystore(
                keyPair.getPrivate(), certificateChain, keystorePassword
            );

            // Then
            assertNotNull(keystoreData, "Keystore data should not be null");
            assertTrue(keystoreData.length > 0, "Keystore data should not be empty");
            
            // Verify it's a valid PKCS12 keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(keystoreData), keystorePassword.toCharArray());
            
            assertTrue(keystore.containsAlias("privatekey"), "Keystore should contain private key");
            assertTrue(keystore.containsAlias("certificate"), "Keystore should contain certificate");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when privateKey is null")
        void shouldThrowExceptionWhenPrivateKeyIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.createPKCS12Keystore(null, certificate, keystorePassword),
                "Should throw IllegalArgumentException when privateKey is null"
            );

            assertEquals("Private key cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificate is null")
        void shouldThrowExceptionWhenCertificateIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.createPKCS12Keystore(keyPair.getPrivate(), (X509Certificate) null, keystorePassword),
                "Should throw IllegalArgumentException when certificate is null"
            );

            assertEquals("Certificate cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificateChain is null")
        void shouldThrowExceptionWhenCertificateChainIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.createPKCS12Keystore(keyPair.getPrivate(), (List<X509Certificate>) null, keystorePassword),
                "Should throw IllegalArgumentException when certificateChain is null"
            );

            assertEquals("Certificate chain cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificateChain is empty")
        void shouldThrowExceptionWhenCertificateChainIsEmpty() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.createPKCS12Keystore(keyPair.getPrivate(), Arrays.asList(), keystorePassword),
                "Should throw IllegalArgumentException when certificateChain is empty"
            );

            assertEquals("Certificate chain cannot be empty", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"short", "a"})
        @DisplayName("Should throw IllegalArgumentException for invalid password")
        void shouldThrowExceptionForInvalidPassword(String invalidPassword) {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.createPKCS12Keystore(keyPair.getPrivate(), certificate, invalidPassword),
                "Should throw IllegalArgumentException for invalid password: " + invalidPassword
            );

            assertEquals("Password must be at least 6 characters long", exception.getMessage());
        }

        @Test
        @DisplayName("Should create keystore with different passwords")
        void shouldCreateKeystoreWithDifferentPasswords() throws Exception {
            // Given
            String password1 = "password123";
            String password2 = "differentPassword456";

            // When
            byte[] keystoreData1 = keystoreService.createPKCS12Keystore(
                keyPair.getPrivate(), certificate, password1
            );
            byte[] keystoreData2 = keystoreService.createPKCS12Keystore(
                keyPair.getPrivate(), certificate, password2
            );

            // Then
            assertNotNull(keystoreData1, "Keystore data 1 should not be null");
            assertNotNull(keystoreData2, "Keystore data 2 should not be null");
            assertNotEquals(keystoreData1, keystoreData2, "Different passwords should produce different keystores");
        }

        @Test
        @DisplayName("Should create keystore with multiple certificates in chain")
        void shouldCreateKeystoreWithMultipleCertificatesInChain() throws Exception {
            // Given
            KeyPair rootKeyPair = keyPairGeneratorService.generateKeyPair(4096);
            KeyPair intermediateKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair endEntityKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            
            var rootDN = certificateGeneratorService.buildX500Name(
                "Root CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "root@example.com"
            );
            
            var intermediateDN = certificateGeneratorService.buildX500Name(
                "Intermediate CA", "Test Organization", "Engineering", 
                "Test City", "Test State", "US", "intermediate@example.com"
            );
            
            var endEntityDN = certificateGeneratorService.buildX500Name(
                "server.example.com", "Test Organization", "Engineering", 
                "Test City", "Test State", "US", "admin@server.example.com"
            );
            
            X509Certificate rootCert = certificateGeneratorService.generateRootCertificate(
                rootKeyPair, rootDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
            
            X509Certificate intermediateCert = certificateGeneratorService.generateIntermediateCertificate(
                intermediateKeyPair, intermediateDN, rootDN, 
                rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
                1825, Arrays.asList("keyCertSign", "cRLSign"), 1
            );
            
            X509Certificate endEntityCert = certificateGeneratorService.generateEndEntityCertificate(
                endEntityKeyPair, endEntityDN, intermediateDN, 
                intermediateKeyPair.getPrivate(), intermediateKeyPair.getPublic(),
                365, Arrays.asList("digitalSignature", "keyEncipherment"), 
                Arrays.asList("serverAuth"), Arrays.asList("server.example.com"), null
            );
            
            List<X509Certificate> certificateChain = Arrays.asList(endEntityCert, intermediateCert, rootCert);

            // When
            byte[] keystoreData = keystoreService.createPKCS12Keystore(
                endEntityKeyPair.getPrivate(), certificateChain, keystorePassword
            );

            // Then
            assertNotNull(keystoreData, "Keystore data should not be null");
            assertTrue(keystoreData.length > 0, "Keystore data should not be empty");
            
            // Verify it's a valid PKCS12 keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(keystoreData), keystorePassword.toCharArray());
            
            assertTrue(keystore.containsAlias("privatekey"), "Keystore should contain private key");
            assertTrue(keystore.containsAlias("certificate"), "Keystore should contain certificate");
        }
    }

    @Nested
    @DisplayName("exportCertificateAsPEM Tests")
    class ExportCertificateAsPEMTests {

        private X509Certificate certificate;

        @BeforeEach
        void setUp() throws Exception {
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            var subjectDN = certificateGeneratorService.buildX500Name(
                "Test Certificate", "Test Organization", "Test Department", 
                "Test City", "Test State", "US", "test@example.com"
            );
            
            certificate = certificateGeneratorService.generateRootCertificate(
                keyPair, subjectDN, 365, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
        }

        @Test
        @DisplayName("Should export certificate as PEM successfully")
        void shouldExportCertificateAsPEMSuccessfully() throws Exception {
            // When
            String pemData = keystoreService.exportCertificateAsPEM(certificate);

            // Then
            assertNotNull(pemData, "PEM data should not be null");
            assertFalse(pemData.isEmpty(), "PEM data should not be empty");
            assertTrue(pemData.contains("-----BEGIN CERTIFICATE-----"), "PEM should contain BEGIN header");
            assertTrue(pemData.contains("-----END CERTIFICATE-----"), "PEM should contain END footer");
            assertTrue(pemData.contains("-----BEGIN CERTIFICATE-----") && pemData.contains("-----END CERTIFICATE-----"), 
                "PEM should contain both BEGIN and END markers");
        }

        @Test
        @DisplayName("Should export certificate with proper PEM format")
        void shouldExportCertificateWithProperPEMFormat() throws Exception {
            // When
            String pemData = keystoreService.exportCertificateAsPEM(certificate);

            // Then
            String[] lines = pemData.split("\n");
            assertEquals("-----BEGIN CERTIFICATE-----", lines[0], "First line should be BEGIN marker");
            assertEquals("-----END CERTIFICATE-----", lines[lines.length - 1], "Last line should be END marker");
            
            // Check that middle lines are base64 encoded
            for (int i = 1; i < lines.length - 1; i++) {
                String line = lines[i].trim();
                if (!line.isEmpty()) {
                    assertTrue(line.matches("[A-Za-z0-9+/=]+"), "PEM lines should be base64 encoded");
                }
            }
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when certificate is null")
        void shouldThrowExceptionWhenCertificateIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.exportCertificateAsPEM(null),
                "Should throw IllegalArgumentException when certificate is null"
            );

            assertEquals("Certificate cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should export different certificates differently")
        void shouldExportDifferentCertificatesDifferently() throws Exception {
            // Given
            KeyPair keyPair1 = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair keyPair2 = keyPairGeneratorService.generateKeyPair(2048);
            
            var subjectDN1 = certificateGeneratorService.buildX500Name(
                "Certificate 1", "Test Organization", "Test Department", 
                "Test City", "Test State", "US", "test1@example.com"
            );
            
            var subjectDN2 = certificateGeneratorService.buildX500Name(
                "Certificate 2", "Test Organization", "Test Department", 
                "Test City", "Test State", "US", "test2@example.com"
            );
            
            X509Certificate certificate1 = certificateGeneratorService.generateRootCertificate(
                keyPair1, subjectDN1, 365, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
            
            X509Certificate certificate2 = certificateGeneratorService.generateRootCertificate(
                keyPair2, subjectDN2, 365, Arrays.asList("keyCertSign", "cRLSign"), 2
            );

            // When
            String pemData1 = keystoreService.exportCertificateAsPEM(certificate1);
            String pemData2 = keystoreService.exportCertificateAsPEM(certificate2);

            // Then
            assertNotEquals(pemData1, pemData2, "Different certificates should produce different PEM data");
        }
    }

    @Nested
    @DisplayName("exportPrivateKeyAsPEM Tests")
    class ExportPrivateKeyAsPEMTests {

        private KeyPair keyPair;

        @BeforeEach
        void setUp() {
            keyPair = keyPairGeneratorService.generateKeyPair(2048);
        }

        @Test
        @DisplayName("Should export private key as PEM successfully")
        void shouldExportPrivateKeyAsPEMSuccessfully() throws Exception {
            // When
            String pemData = keystoreService.exportPrivateKeyAsPEM(keyPair.getPrivate());

            // Then
            assertNotNull(pemData, "PEM data should not be null");
            assertFalse(pemData.isEmpty(), "PEM data should not be empty");
            assertTrue(pemData.contains("-----BEGIN PRIVATE KEY-----"), "PEM should contain BEGIN header");
            assertTrue(pemData.contains("-----END PRIVATE KEY-----"), "PEM should contain END footer");
        }

        @Test
        @DisplayName("Should export private key with proper PEM format")
        void shouldExportPrivateKeyWithProperPEMFormat() throws Exception {
            // When
            String pemData = keystoreService.exportPrivateKeyAsPEM(keyPair.getPrivate());

            // Then
            String[] lines = pemData.split("\n");
            assertEquals("-----BEGIN PRIVATE KEY-----", lines[0], "First line should be BEGIN marker");
            assertEquals("-----END PRIVATE KEY-----", lines[lines.length - 1], "Last line should be END marker");
            
            // Check that middle lines are base64 encoded
            for (int i = 1; i < lines.length - 1; i++) {
                String line = lines[i].trim();
                if (!line.isEmpty()) {
                    assertTrue(line.matches("[A-Za-z0-9+/=]+"), "PEM lines should be base64 encoded");
                }
            }
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when privateKey is null")
        void shouldThrowExceptionWhenPrivateKeyIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keystoreService.exportPrivateKeyAsPEM(null),
                "Should throw IllegalArgumentException when privateKey is null"
            );

            assertEquals("Private key cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should export different private keys differently")
        void shouldExportDifferentPrivateKeysDifferently() throws Exception {
            // Given
            KeyPair keyPair1 = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair keyPair2 = keyPairGeneratorService.generateKeyPair(2048);

            // When
            String pemData1 = keystoreService.exportPrivateKeyAsPEM(keyPair1.getPrivate());
            String pemData2 = keystoreService.exportPrivateKeyAsPEM(keyPair2.getPrivate());

            // Then
            assertNotEquals(pemData1, pemData2, "Different private keys should produce different PEM data");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should create and load PKCS12 keystore successfully")
        void shouldCreateAndLoadPKCS12KeystoreSuccessfully() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            var subjectDN = certificateGeneratorService.buildX500Name(
                "Integration Test Certificate", "Test Organization", "Test Department", 
                "Test City", "Test State", "US", "integration@example.com"
            );
            
            X509Certificate certificate = certificateGeneratorService.generateRootCertificate(
                keyPair, subjectDN, 365, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
            
            String keystorePassword = "integrationTest123";

            // When
            byte[] keystoreData = keystoreService.createPKCS12Keystore(
                keyPair.getPrivate(), certificate, keystorePassword
            );
            
            // Load the keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(keystoreData), keystorePassword.toCharArray());

            // Then
            assertTrue(keystore.containsAlias("privatekey"), "Keystore should contain private key");
            assertTrue(keystore.containsAlias("certificate"), "Keystore should contain certificate");
            
            PrivateKey loadedPrivateKey = (PrivateKey) keystore.getKey("privatekey", keystorePassword.toCharArray());
            X509Certificate loadedCertificate = (X509Certificate) keystore.getCertificate("certificate");
            
            assertNotNull(loadedPrivateKey, "Loaded private key should not be null");
            assertNotNull(loadedCertificate, "Loaded certificate should not be null");
            
            assertEquals(keyPair.getPrivate().getAlgorithm(), loadedPrivateKey.getAlgorithm(), 
                "Loaded private key algorithm should match original");
            assertEquals(certificate.getSerialNumber(), loadedCertificate.getSerialNumber(), 
                "Loaded certificate serial number should match original");
        }

        @Test
        @DisplayName("Should handle keystore with certificate chain")
        void shouldHandleKeystoreWithCertificateChain() throws Exception {
            // Given
            KeyPair rootKeyPair = keyPairGeneratorService.generateKeyPair(4096);
            KeyPair intermediateKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair endEntityKeyPair = keyPairGeneratorService.generateKeyPair(2048);
            
            var rootDN = certificateGeneratorService.buildX500Name(
                "Root CA", "Test Organization", "IT Security", 
                "Test City", "Test State", "US", "root@example.com"
            );
            
            var intermediateDN = certificateGeneratorService.buildX500Name(
                "Intermediate CA", "Test Organization", "Engineering", 
                "Test City", "Test State", "US", "intermediate@example.com"
            );
            
            var endEntityDN = certificateGeneratorService.buildX500Name(
                "server.example.com", "Test Organization", "Engineering", 
                "Test City", "Test State", "US", "admin@server.example.com"
            );
            
            X509Certificate rootCert = certificateGeneratorService.generateRootCertificate(
                rootKeyPair, rootDN, 3650, Arrays.asList("keyCertSign", "cRLSign"), 2
            );
            
            X509Certificate intermediateCert = certificateGeneratorService.generateIntermediateCertificate(
                intermediateKeyPair, intermediateDN, rootDN, 
                rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
                1825, Arrays.asList("keyCertSign", "cRLSign"), 1
            );
            
            X509Certificate endEntityCert = certificateGeneratorService.generateEndEntityCertificate(
                endEntityKeyPair, endEntityDN, intermediateDN, 
                intermediateKeyPair.getPrivate(), intermediateKeyPair.getPublic(),
                365, Arrays.asList("digitalSignature", "keyEncipherment"), 
                Arrays.asList("serverAuth"), Arrays.asList("server.example.com"), null
            );
            
            List<X509Certificate> certificateChain = Arrays.asList(endEntityCert, intermediateCert, rootCert);
            String keystorePassword = "chainTest123";

            // When
            byte[] keystoreData = keystoreService.createPKCS12Keystore(
                endEntityKeyPair.getPrivate(), certificateChain, keystorePassword
            );
            
            // Load the keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(keystoreData), keystorePassword.toCharArray());

            // Then
            assertTrue(keystore.containsAlias("privatekey"), "Keystore should contain private key");
            assertTrue(keystore.containsAlias("certificate"), "Keystore should contain certificate");
            
            PrivateKey loadedPrivateKey = (PrivateKey) keystore.getKey("privatekey", keystorePassword.toCharArray());
            X509Certificate loadedCertificate = (X509Certificate) keystore.getCertificate("certificate");
            
            assertNotNull(loadedPrivateKey, "Loaded private key should not be null");
            assertNotNull(loadedCertificate, "Loaded certificate should not be null");
            
            assertEquals(endEntityKeyPair.getPrivate().getAlgorithm(), loadedPrivateKey.getAlgorithm(), 
                "Loaded private key algorithm should match original");
            assertEquals(endEntityCert.getSerialNumber(), loadedCertificate.getSerialNumber(), 
                "Loaded certificate serial number should match original");
        }
    }
}
