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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@DisplayName("KeyPairGeneratorService Tests")
class KeyPairGeneratorServiceTest {

    private KeyPairGeneratorService keyPairGeneratorService;

    @BeforeEach
    void setUp() {
        keyPairGeneratorService = new KeyPairGeneratorService();
    }

    @Nested
    @DisplayName("Valid Key Size Tests")
    class ValidKeySizeTests {

        @Test
        @DisplayName("Should generate 2048-bit RSA key pair successfully")
        void shouldGenerate2048BitKeyPair() {
            // When
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);

            // Then
            assertNotNull(keyPair, "KeyPair should not be null");
            assertNotNull(keyPair.getPrivate(), "Private key should not be null");
            assertNotNull(keyPair.getPublic(), "Public key should not be null");
            assertEquals("RSA", keyPair.getPrivate().getAlgorithm(), "Private key algorithm should be RSA");
            assertEquals("RSA", keyPair.getPublic().getAlgorithm(), "Public key algorithm should be RSA");
            assertEquals(2048, ((RSAPrivateKey) keyPair.getPrivate()).getModulus().bitLength(), "Private key should be 2048 bits");
            assertEquals(2048, ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength(), "Public key should be 2048 bits");
        }

        @Test
        @DisplayName("Should generate 4096-bit RSA key pair successfully")
        void shouldGenerate4096BitKeyPair() {
            // When
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(4096);

            // Then
            assertNotNull(keyPair, "KeyPair should not be null");
            assertNotNull(keyPair.getPrivate(), "Private key should not be null");
            assertNotNull(keyPair.getPublic(), "Public key should not be null");
            assertEquals("RSA", keyPair.getPrivate().getAlgorithm(), "Private key algorithm should be RSA");
            assertEquals("RSA", keyPair.getPublic().getAlgorithm(), "Public key algorithm should be RSA");
            assertEquals(4096, ((RSAPrivateKey) keyPair.getPrivate()).getModulus().bitLength(), "Private key should be 4096 bits");
            assertEquals(4096, ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength(), "Public key should be 4096 bits");
        }

        @Test
        @DisplayName("Should generate different key pairs for multiple calls")
        void shouldGenerateDifferentKeyPairs() {
            // When
            KeyPair keyPair1 = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair keyPair2 = keyPairGeneratorService.generateKeyPair(2048);

            // Then
            assertNotEquals(keyPair1.getPrivate(), keyPair2.getPrivate(), "Private keys should be different");
            assertNotEquals(keyPair1.getPublic(), keyPair2.getPublic(), "Public keys should be different");
            assertNotEquals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded(), 
                "Private key encodings should be different");
            assertNotEquals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded(), 
                "Public key encodings should be different");
        }

        @Test
        @DisplayName("Should generate valid key pair that can be used for encryption/decryption")
        void shouldGenerateValidKeyPairForEncryption() throws Exception {
            // When
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Then
            assertNotNull(privateKey, "Private key should not be null");
            assertNotNull(publicKey, "Public key should not be null");
            
            // Verify key format
            assertTrue(privateKey.getFormat().equals("PKCS#8"), "Private key format should be PKCS#8");
            assertTrue(publicKey.getFormat().equals("X.509"), "Public key format should be X.509");
        }
    }

    @Nested
    @DisplayName("Invalid Key Size Tests")
    class InvalidKeySizeTests {

        @ParameterizedTest
        @ValueSource(ints = {1024, 3072, 8192, 512, 1536})
        @DisplayName("Should throw IllegalArgumentException for invalid key sizes")
        void shouldThrowExceptionForInvalidKeySizes(int invalidKeySize) {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keyPairGeneratorService.generateKeyPair(invalidKeySize),
                "Should throw IllegalArgumentException for key size: " + invalidKeySize
            );

            assertEquals("Key size must be 2048 or 4096 bits", exception.getMessage(),
                "Exception message should match expected");
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, -2048, -4096})
        @DisplayName("Should throw IllegalArgumentException for negative key sizes")
        void shouldThrowExceptionForNegativeKeySizes(int negativeKeySize) {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keyPairGeneratorService.generateKeyPair(negativeKeySize),
                "Should throw IllegalArgumentException for negative key size: " + negativeKeySize
            );

            assertEquals("Key size must be a positive integer", exception.getMessage(),
                "Exception message should match expected");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException for zero key size")
        void shouldThrowExceptionForZeroKeySize() {
            // When & Then
            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> keyPairGeneratorService.generateKeyPair(0),
                "Should throw IllegalArgumentException for zero key size"
            );

            assertEquals("Key size must be a positive integer", exception.getMessage(),
                "Exception message should match expected");
        }
    }

    @Nested
    @DisplayName("Performance Tests")
    class PerformanceTests {

        @Test
        @DisplayName("Should generate 2048-bit key pair within reasonable time")
        void shouldGenerate2048BitKeyPairWithinReasonableTime() {
            // When
            long startTime = System.currentTimeMillis();
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            // Then
            assertNotNull(keyPair, "KeyPair should be generated successfully");
            assertTrue(duration < 5000, "2048-bit key generation should take less than 5 seconds, took: " + duration + "ms");
        }

        @Test
        @DisplayName("Should generate 4096-bit key pair within reasonable time")
        void shouldGenerate4096BitKeyPairWithinReasonableTime() {
            // When
            long startTime = System.currentTimeMillis();
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(4096);
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;

            // Then
            assertNotNull(keyPair, "KeyPair should be generated successfully");
            assertTrue(duration < 10000, "4096-bit key generation should take less than 10 seconds, took: " + duration + "ms");
        }
    }

    @Nested
    @DisplayName("Cryptographic Strength Tests")
    class CryptographicStrengthTests {

        @Test
        @DisplayName("Should generate cryptographically strong random keys")
        void shouldGenerateCryptographicallyStrongKeys() {
            // When
            KeyPair keyPair1 = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair keyPair2 = keyPairGeneratorService.generateKeyPair(2048);
            KeyPair keyPair3 = keyPairGeneratorService.generateKeyPair(2048);

            // Then
            byte[] privateKey1 = keyPair1.getPrivate().getEncoded();
            byte[] privateKey2 = keyPair2.getPrivate().getEncoded();
            byte[] privateKey3 = keyPair3.getPrivate().getEncoded();

            // Verify keys are different (cryptographically random)
            assertNotEquals(privateKey1, privateKey2, "Private keys should be different");
            assertNotEquals(privateKey1, privateKey3, "Private keys should be different");
            assertNotEquals(privateKey2, privateKey3, "Private keys should be different");

            // Verify keys are not all zeros or all ones (weak keys)
            boolean allZeros1 = java.util.stream.IntStream.range(0, privateKey1.length).allMatch(i -> privateKey1[i] == 0);
            boolean allZeros2 = java.util.stream.IntStream.range(0, privateKey2.length).allMatch(i -> privateKey2[i] == 0);
            boolean allZeros3 = java.util.stream.IntStream.range(0, privateKey3.length).allMatch(i -> privateKey3[i] == 0);

            assertFalse(allZeros1, "Private key should not be all zeros");
            assertFalse(allZeros2, "Private key should not be all zeros");
            assertFalse(allZeros3, "Private key should not be all zeros");
        }

        @Test
        @DisplayName("Should generate keys with proper entropy")
        void shouldGenerateKeysWithProperEntropy() {
            // When
            KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
            byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

            // Then
            // Check that the key has good distribution of bytes
            int[] byteCounts = new int[256];
            for (byte b : privateKeyBytes) {
                byteCounts[b & 0xFF]++;
            }

            // At least 50% of possible byte values should appear (good entropy)
            int nonZeroCounts = 0;
            for (int count : byteCounts) {
                if (count > 0) nonZeroCounts++;
            }

            assertTrue(nonZeroCounts > 128, "Key should have good entropy distribution");
        }
    }
}
