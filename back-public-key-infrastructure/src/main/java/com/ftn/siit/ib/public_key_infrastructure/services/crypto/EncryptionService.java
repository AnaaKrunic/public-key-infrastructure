package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    private static final int MASTER_KEY_LENGTH = 32; // 256 bits

    /**
     * Encrypts a private key using AES-256-GCM with the provided master key.
     * 
     * @param privateKey The private key to encrypt
     * @param masterKey The master key (Base64-encoded 256-bit key)
     * @return EncryptedData containing the encrypted key, IV, and authentication tag
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if encryption fails
     */
    public EncryptedData encryptPrivateKey(java.security.PrivateKey privateKey, String masterKey) {
        validateEncryptParameters(privateKey, masterKey);
        
        try {
            byte[] keyBytes = Base64.getDecoder().decode(masterKey);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            
            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            byte[] privateKeyBytes = privateKey.getEncoded();
            byte[] encryptedDataWithTag = cipher.doFinal(privateKeyBytes);
            
            // Split encrypted data and tag
            byte[] encryptedData = new byte[encryptedDataWithTag.length - GCM_TAG_LENGTH];
            byte[] tag = new byte[GCM_TAG_LENGTH];
            System.arraycopy(encryptedDataWithTag, 0, encryptedData, 0, encryptedData.length);
            System.arraycopy(encryptedDataWithTag, encryptedData.length, tag, 0, GCM_TAG_LENGTH);
            
            return new EncryptedData(encryptedData, iv, tag);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt private key", e);
        }
    }

    /**
     * Decrypts a private key using AES-256-GCM with the provided master key.
     * 
     * @param encryptedData The encrypted private key data
     * @param iv The initialization vector
     * @param tag The authentication tag
     * @param masterKey The master key (Base64-encoded 256-bit key)
     * @return The decrypted private key
     * @throws IllegalArgumentException if parameters are invalid
     * @throws SecurityException if decryption fails (invalid key or corrupted data)
     */
    public java.security.PrivateKey decryptPrivateKey(byte[] encryptedData, byte[] iv, byte[] tag, String masterKey) {
        validateDecryptParameters(encryptedData, iv, tag, masterKey);
        
        try {
            byte[] keyBytes = Base64.getDecoder().decode(masterKey);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            // Combine encrypted data and tag
            byte[] ciphertextWithTag = new byte[encryptedData.length + tag.length];
            System.arraycopy(encryptedData, 0, ciphertextWithTag, 0, encryptedData.length);
            System.arraycopy(tag, 0, ciphertextWithTag, encryptedData.length, tag.length);
            
            byte[] decryptedBytes = cipher.doFinal(ciphertextWithTag);
            
            // Convert back to PrivateKey
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(decryptedBytes);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new SecurityException("Failed to decrypt private key - invalid master key or corrupted data", e);
        }
    }

    /**
     * Generates a new master key for encryption.
     * 
     * @return A Base64-encoded 256-bit master key
     */
    public String generateMasterKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(MASTER_KEY_LENGTH * 8); // 256 bits
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("AES algorithm not available", e);
        }
    }

    /**
     * Validates parameters for encryption.
     */
    private void validateEncryptParameters(java.security.PrivateKey privateKey, String masterKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (masterKey == null || masterKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Master key must be a valid Base64-encoded 256-bit key");
        }
        if (!isValidMasterKey(masterKey)) {
            throw new IllegalArgumentException("Master key must be a valid Base64-encoded 256-bit key");
        }
    }

    /**
     * Validates parameters for decryption.
     */
    private void validateDecryptParameters(byte[] encryptedData, byte[] iv, byte[] tag, String masterKey) {
        if (encryptedData == null) {
            throw new IllegalArgumentException("Encrypted data cannot be null");
        }
        if (iv == null) {
            throw new IllegalArgumentException("IV cannot be null");
        }
        if (tag == null) {
            throw new IllegalArgumentException("Tag cannot be null");
        }
        if (masterKey == null || masterKey.trim().isEmpty()) {
            throw new IllegalArgumentException("Master key must be a valid Base64-encoded 256-bit key");
        }
        if (!isValidMasterKey(masterKey)) {
            throw new IllegalArgumentException("Master key must be a valid Base64-encoded 256-bit key");
        }
        if (iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException("IV must be 12 bytes");
        }
        if (tag.length != GCM_TAG_LENGTH) {
            throw new IllegalArgumentException("Tag must be 16 bytes");
        }
    }

    /**
     * Validates that the master key is a valid Base64-encoded 256-bit key.
     */
    private boolean isValidMasterKey(String masterKey) {
        try {
            byte[] decoded = Base64.getDecoder().decode(masterKey);
            return decoded.length == MASTER_KEY_LENGTH;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Data class to hold encrypted data, IV, and authentication tag.
     */
    public static class EncryptedData {
        private final byte[] encryptedData;
        private final byte[] iv;
        private final byte[] tag;

        public EncryptedData(byte[] encryptedData, byte[] iv, byte[] tag) {
            this.encryptedData = encryptedData;
            this.iv = iv;
            this.tag = tag;
        }

        public byte[] getEncryptedData() {
            return encryptedData;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getTag() {
            return tag;
        }
    }
}
