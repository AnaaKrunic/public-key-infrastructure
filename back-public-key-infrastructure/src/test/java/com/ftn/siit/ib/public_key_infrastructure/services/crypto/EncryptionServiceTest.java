package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import static org.junit.jupiter.api.Assertions.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

@DisplayName("EncryptionService Tests")
class EncryptionServiceTest {

    private EncryptionService encryptionService;
    private KeyPairGeneratorService keyPairGeneratorService;
    private String testMasterKey;

    @BeforeEach
    void setUp() {
        encryptionService = new EncryptionService();
        keyPairGeneratorService = new KeyPairGeneratorService();
        
        // Generate a test master key (32 bytes = 256 bits)
        testMasterKey = Base64.getEncoder().encodeToString(
            new byte[]{
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
            }
        );
    }

    @Nested
    @DisplayName("encryptPrivateKey Tests")
    class EncryptPrivateKeyTests {

        @Test
        @DisplayName("Should encrypt private key successfully")
        void shouldEncryptPrivateKeySuccessfully() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();

            // When
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(privateKey, testMasterKey);

            // Then
            assertNotNull(encryptedData, "EncryptedData should not be null");
            assertNotNull(encryptedData.getEncryptedData(), "Encrypted data should not be null");
            assertNotNull(encryptedData.getIv(), "IV should not be null");
            assertNotNull(encryptedData.getTag(), "Tag should not be null");
            
            assertTrue(encryptedData.getEncryptedData().length > 0, "Encrypted data should not be empty");
            assertEquals(12, encryptedData.getIv().length, "IV should be 12 bytes");
            assertEquals(16, encryptedData.getTag().length, "Tag should be 16 bytes");
        }

        @Test
        @DisplayName("Should generate different encrypted data for same private key")
        void shouldGenerateDifferentEncryptedDataForSamePrivateKey() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();

            // When
            EncryptionService.EncryptedData encryptedData1 = encryptionService.encryptPrivateKey(privateKey, testMasterKey);
            EncryptionService.EncryptedData encryptedData2 = encryptionService.encryptPrivateKey(privateKey, testMasterKey);

            // Then
            assertNotEquals(encryptedData1.getEncryptedData(), encryptedData2.getEncryptedData(), 
                "Encrypted data should be different due to random IV");
            assertNotEquals(encryptedData1.getIv(), encryptedData2.getIv(), 
                "IVs should be different");
            assertNotEquals(encryptedData1.getTag(), encryptedData2.getTag(), 
                "Tags should be different");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when privateKey is null")
        void shouldThrowExceptionWhenPrivateKeyIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.encryptPrivateKey(null, testMasterKey),
                "Should throw IllegalArgumentException when privateKey is null"
            );

            assertEquals("Private key cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when masterKey is null")
        void shouldThrowExceptionWhenMasterKeyIsNull() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.encryptPrivateKey(privateKey, null),
                "Should throw IllegalArgumentException when masterKey is null"
            );

            assertEquals("Master key must be a valid Base64-encoded 256-bit key", exception.getMessage());
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"invalid", "short", "not-base64"})
        @DisplayName("Should throw IllegalArgumentException for invalid master key")
        void shouldThrowExceptionForInvalidMasterKey(String invalidMasterKey) throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.encryptPrivateKey(privateKey, invalidMasterKey),
                "Should throw IllegalArgumentException for invalid master key: " + invalidMasterKey
            );

            assertEquals("Master key must be a valid Base64-encoded 256-bit key", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for wrong master key length")
        void shouldThrowExceptionForWrongMasterKeyLength() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();
            String wrongLengthKey = Base64.getEncoder().encodeToString(new byte[16]); // 128 bits

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.encryptPrivateKey(privateKey, wrongLengthKey),
                "Should throw IllegalArgumentException for wrong master key length"
            );

            assertEquals("Master key must be a valid Base64-encoded 256-bit key", exception.getMessage());
        }

        @Test
        @DisplayName("Should encrypt different private keys differently")
        void shouldEncryptDifferentPrivateKeysDifferently() throws Exception {
            // Given
            KeyPair keyPair1 = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair keyPair2 = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey1 = keyPair1.getPrivate();
            PrivateKey privateKey2 = keyPair2.getPrivate();

            // When
            EncryptionService.EncryptedData encryptedData1 = encryptionService.encryptPrivateKey(privateKey1, testMasterKey);
            EncryptionService.EncryptedData encryptedData2 = encryptionService.encryptPrivateKey(privateKey2, testMasterKey);

            // Then
            assertNotEquals(encryptedData1.getEncryptedData(), encryptedData2.getEncryptedData(), 
                "Different private keys should produce different encrypted data");
        }
    }

    @Nested
    @DisplayName("decryptPrivateKey Tests")
    class DecryptPrivateKeyTests {

        private KeyPair keyPair;
        private PrivateKey originalPrivateKey;
        private EncryptionService.EncryptedData encryptedData;

        @BeforeEach
        void setUp() throws Exception {
            keyPair = keyPairGeneratorService.generateKeyPair(2048);
            originalPrivateKey = keyPair.getPrivate();
            encryptedData = encryptionService.encryptPrivateKey(originalPrivateKey, testMasterKey);
        }

        @Test
        @DisplayName("Should decrypt private key successfully")
        void shouldDecryptPrivateKeySuccessfully() throws Exception {
            // When
            PrivateKey decryptedPrivateKey = encryptionService.decryptPrivateKey(
                encryptedData.getEncryptedData(), 
                encryptedData.getIv(), 
                encryptedData.getTag(), 
                testMasterKey
            );

            // Then
            assertNotNull(decryptedPrivateKey, "Decrypted private key should not be null");
            assertEquals(originalPrivateKey.getAlgorithm(), decryptedPrivateKey.getAlgorithm(), 
                "Decrypted key algorithm should match original");
            assertEquals(originalPrivateKey.getFormat(), decryptedPrivateKey.getFormat(), 
                "Decrypted key format should match original");
            assertArrayEquals(originalPrivateKey.getEncoded(), decryptedPrivateKey.getEncoded(), 
                "Decrypted key should match original key");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when encryptedData is null")
        void shouldThrowExceptionWhenEncryptedDataIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.decryptPrivateKey(null, encryptedData.getIv(), encryptedData.getTag(), testMasterKey),
                "Should throw IllegalArgumentException when encryptedData is null"
            );

            assertEquals("Encrypted data cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when iv is null")
        void shouldThrowExceptionWhenIvIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), null, encryptedData.getTag(), testMasterKey),
                "Should throw IllegalArgumentException when iv is null"
            );

            assertEquals("IV cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when tag is null")
        void shouldThrowExceptionWhenTagIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), encryptedData.getIv(), null, testMasterKey),
                "Should throw IllegalArgumentException when tag is null"
            );

            assertEquals("Tag cannot be null", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when masterKey is null")
        void shouldThrowExceptionWhenMasterKeyIsNull() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), encryptedData.getIv(), encryptedData.getTag(), null),
                "Should throw IllegalArgumentException when masterKey is null"
            );

            assertEquals("Master key must be a valid Base64-encoded 256-bit key", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw SecurityException when decryption fails due to wrong master key")
        void shouldThrowSecurityExceptionWhenDecryptionFailsDueToWrongMasterKey() {
            // Given
            String wrongMasterKey = Base64.getEncoder().encodeToString(new byte[32]);

            // When & Then
            SecurityException exception = assertThrows(
                SecurityException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), encryptedData.getIv(), encryptedData.getTag(), wrongMasterKey),
                "Should throw SecurityException when decryption fails due to wrong master key"
            );

            assertEquals("Failed to decrypt private key - invalid master key or corrupted data", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw SecurityException when decryption fails due to tampered data")
        void shouldThrowSecurityExceptionWhenDecryptionFailsDueToTamperedData() {
            // Given
            byte[] tamperedEncryptedData = encryptedData.getEncryptedData().clone();
            tamperedEncryptedData[0] = (byte) (tamperedEncryptedData[0] ^ 0xFF); // Flip first byte

            // When & Then
            SecurityException exception = assertThrows(
                SecurityException.class,
                () -> encryptionService.decryptPrivateKey(tamperedEncryptedData, encryptedData.getIv(), encryptedData.getTag(), testMasterKey),
                "Should throw SecurityException when decryption fails due to tampered data"
            );

            assertEquals("Failed to decrypt private key - invalid master key or corrupted data", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw SecurityException when decryption fails due to tampered IV")
        void shouldThrowSecurityExceptionWhenDecryptionFailsDueToTamperedIV() {
            // Given
            byte[] tamperedIV = encryptedData.getIv().clone();
            tamperedIV[0] = (byte) (tamperedIV[0] ^ 0xFF); // Flip first byte

            // When & Then
            SecurityException exception = assertThrows(
                SecurityException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), tamperedIV, encryptedData.getTag(), testMasterKey),
                "Should throw SecurityException when decryption fails due to tampered IV"
            );

            assertEquals("Failed to decrypt private key - invalid master key or corrupted data", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw SecurityException when decryption fails due to tampered tag")
        void shouldThrowSecurityExceptionWhenDecryptionFailsDueToTamperedTag() {
            // Given
            byte[] tamperedTag = encryptedData.getTag().clone();
            tamperedTag[0] = (byte) (tamperedTag[0] ^ 0xFF); // Flip first byte

            // When & Then
            SecurityException exception = assertThrows(
                SecurityException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), encryptedData.getIv(), tamperedTag, testMasterKey),
                "Should throw SecurityException when decryption fails due to tampered tag"
            );

            assertEquals("Failed to decrypt private key - invalid master key or corrupted data", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for invalid IV length")
        void shouldThrowExceptionForInvalidIVLength() {
            // Given
            byte[] invalidIV = new byte[8]; // Wrong length

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), invalidIV, encryptedData.getTag(), testMasterKey),
                "Should throw IllegalArgumentException for invalid IV length"
            );

            assertEquals("IV must be 12 bytes", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for invalid tag length")
        void shouldThrowExceptionForInvalidTagLength() {
            // Given
            byte[] invalidTag = new byte[8]; // Wrong length

            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), encryptedData.getIv(), invalidTag, testMasterKey),
                "Should throw IllegalArgumentException for invalid tag length"
            );

            assertEquals("Tag must be 16 bytes", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("generateMasterKey Tests")
    class GenerateMasterKeyTests {

        @Test
        @DisplayName("Should generate valid master key")
        void shouldGenerateValidMasterKey() {
            // When
            String masterKey = encryptionService.generateMasterKey();

            // Then
            assertNotNull(masterKey, "Master key should not be null");
            assertFalse(masterKey.isEmpty(), "Master key should not be empty");
            
            // Verify it's valid Base64
            assertDoesNotThrow(() -> {
                byte[] decoded = Base64.getDecoder().decode(masterKey);
                assertEquals(32, decoded.length, "Master key should be 32 bytes (256 bits)");
            }, "Master key should be valid Base64");
        }

        @Test
        @DisplayName("Should generate different master keys")
        void shouldGenerateDifferentMasterKeys() {
            // When
            String masterKey1 = encryptionService.generateMasterKey();
            String masterKey2 = encryptionService.generateMasterKey();
            String masterKey3 = encryptionService.generateMasterKey();

            // Then
            assertNotEquals(masterKey1, masterKey2, "Master keys should be different");
            assertNotEquals(masterKey1, masterKey3, "Master keys should be different");
            assertNotEquals(masterKey2, masterKey3, "Master keys should be different");
        }

        @Test
        @DisplayName("Should generate cryptographically random master keys")
        void shouldGenerateCryptographicallyRandomMasterKeys() {
            // When
            Set<String> masterKeys = new HashSet<>();
            for (int i = 0; i < 1000; i++) {
                masterKeys.add(encryptionService.generateMasterKey());
            }

            // Then
            assertEquals(1000, masterKeys.size(), "All master keys should be unique");
        }
    }

    @Nested
    @DisplayName("Round-trip Encryption Tests")
    class RoundTripEncryptionTests {

        @Test
        @DisplayName("Should successfully encrypt and decrypt private key")
        void shouldSuccessfullyEncryptAndDecryptPrivateKey() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey originalPrivateKey = keyPair.getPrivate();

            // When
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(originalPrivateKey, testMasterKey);
            PrivateKey decryptedPrivateKey = encryptionService.decryptPrivateKey(
                encryptedData.getEncryptedData(), 
                encryptedData.getIv(), 
                encryptedData.getTag(), 
                testMasterKey
            );

            // Then
            assertArrayEquals(originalPrivateKey.getEncoded(), decryptedPrivateKey.getEncoded(), 
                "Decrypted key should match original key");
            assertEquals(originalPrivateKey.getAlgorithm(), decryptedPrivateKey.getAlgorithm(), 
                "Decrypted key algorithm should match original");
            assertEquals(originalPrivateKey.getFormat(), decryptedPrivateKey.getFormat(), 
                "Decrypted key format should match original");
        }

        @Test
        @DisplayName("Should handle multiple encryption/decryption cycles")
        void shouldHandleMultipleEncryptionDecryptionCycles() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey originalPrivateKey = keyPair.getPrivate();

            // When & Then
            for (int i = 0; i < 10; i++) {
                EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(originalPrivateKey, testMasterKey);
                PrivateKey decryptedPrivateKey = encryptionService.decryptPrivateKey(
                    encryptedData.getEncryptedData(), 
                    encryptedData.getIv(), 
                    encryptedData.getTag(), 
                    testMasterKey
                );
                
                assertArrayEquals(originalPrivateKey.getEncoded(), decryptedPrivateKey.getEncoded(), 
                    "Decrypted key should match original key in cycle " + i);
            }
        }

        @Test
        @DisplayName("Should handle different key sizes")
        void shouldHandleDifferentKeySizes() throws Exception {
            // Given
            int[] keySizes = {2048, 4096};
            
            for (int keySize : keySizes) {
                KeyPair keyPair = keyPairGeneratorService.generateKeyPair(keySize);
                PrivateKey originalPrivateKey = keyPair.getPrivate();

                // When
                EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(originalPrivateKey, testMasterKey);
                PrivateKey decryptedPrivateKey = encryptionService.decryptPrivateKey(
                    encryptedData.getEncryptedData(), 
                    encryptedData.getIv(), 
                    encryptedData.getTag(), 
                    testMasterKey
                );

                // Then
                assertArrayEquals(originalPrivateKey.getEncoded(), decryptedPrivateKey.getEncoded(), 
                    "Decrypted key should match original key for " + keySize + "-bit key");
            }
        }
    }

    @Nested
    @DisplayName("Security Tests")
    class SecurityTests {

        @Test
        @DisplayName("Should use different IVs for same input")
        void shouldUseDifferentIVsForSameInput() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();

            // When
            EncryptionService.EncryptedData encryptedData1 = encryptionService.encryptPrivateKey(privateKey, testMasterKey);
            EncryptionService.EncryptedData encryptedData2 = encryptionService.encryptPrivateKey(privateKey, testMasterKey);

            // Then
            assertNotEquals(encryptedData1.getIv(), encryptedData2.getIv(), 
                "Different IVs should be used for same input");
        }

        @Test
        @DisplayName("Should produce different ciphertext for same input")
        void shouldProduceDifferentCiphertextForSameInput() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();

            // When
            EncryptionService.EncryptedData encryptedData1 = encryptionService.encryptPrivateKey(privateKey, testMasterKey);
            EncryptionService.EncryptedData encryptedData2 = encryptionService.encryptPrivateKey(privateKey, testMasterKey);

            // Then
            assertNotEquals(encryptedData1.getEncryptedData(), encryptedData2.getEncryptedData(), 
                "Different ciphertext should be produced for same input");
        }

        @Test
        @DisplayName("Should detect tampering in encrypted data")
        void shouldDetectTamperingInEncryptedData() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(privateKey, testMasterKey);
            
            // Tamper with encrypted data
            byte[] tamperedData = encryptedData.getEncryptedData().clone();
            tamperedData[0] = (byte) (tamperedData[0] ^ 0xFF);

            // When & Then
            assertThrows(SecurityException.class, () -> {
                encryptionService.decryptPrivateKey(tamperedData, encryptedData.getIv(), encryptedData.getTag(), testMasterKey);
            }, "Should detect tampering in encrypted data");
        }

        @Test
        @DisplayName("Should detect tampering in IV")
        void shouldDetectTamperingInIV() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(privateKey, testMasterKey);
            
            // Tamper with IV
            byte[] tamperedIV = encryptedData.getIv().clone();
            tamperedIV[0] = (byte) (tamperedIV[0] ^ 0xFF);

            // When & Then
            assertThrows(SecurityException.class, () -> {
                encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), tamperedIV, encryptedData.getTag(), testMasterKey);
            }, "Should detect tampering in IV");
        }

        @Test
        @DisplayName("Should detect tampering in tag")
        void shouldDetectTamperingInTag() throws Exception {
            // Given
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();
            EncryptionService.EncryptedData encryptedData = encryptionService.encryptPrivateKey(privateKey, testMasterKey);
            
            // Tamper with tag
            byte[] tamperedTag = encryptedData.getTag().clone();
            tamperedTag[0] = (byte) (tamperedTag[0] ^ 0xFF);

            // When & Then
            assertThrows(SecurityException.class, () -> {
                encryptionService.decryptPrivateKey(encryptedData.getEncryptedData(), encryptedData.getIv(), tamperedTag, testMasterKey);
            }, "Should detect tampering in tag");
        }
    }
}
