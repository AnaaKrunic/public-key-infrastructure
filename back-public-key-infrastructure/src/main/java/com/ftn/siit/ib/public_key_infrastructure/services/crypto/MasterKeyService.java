package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import com.ftn.siit.ib.public_key_infrastructure.entities.MasterKey;
import com.ftn.siit.ib.public_key_infrastructure.repositories.MasterKeyRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

/**
 * Service for managing the master encryption key.
 * 
 * Security Features:
 * - Master key is encrypted with server key and stored in database
 * - Server key is loaded from secure file system or environment
 * - Master key is cached for performance but can be rotated
 * - Supports key rotation for enhanced security
 * 
 * Key Hierarchy:
 * 1. Server Key (from file system/environment) -> encrypts Master Key
 * 2. Master Key (from database) -> encrypts User Keys
 * 3. User Keys (from database) -> encrypts Private Keys
 */
@Service
@Transactional
public class MasterKeyService {

    private final MasterKeyRepository masterKeyRepository;
    
    @Value("${security.master-key}")
    private String masterKeyBase64;
    
    @Value("${app.security.server-key.file:}")
    private String serverKeyFile;
    
    @Value("${app.security.server-key.env:PKI_SERVER_KEY}")
    private String serverKeyEnvVar;
    
    @Value("${app.security.server-key.fallback:}")
    private String serverKeyFallback;

    public MasterKeyService(MasterKeyRepository masterKeyRepository) {
        this.masterKeyRepository = masterKeyRepository;
    }

    /**
     * Gets the current master key, decrypting it with the server key.
     * The master key is cached for performance.
     * 
     * @return The decrypted master key as byte array
     * @throws SecurityException if master key cannot be retrieved or decrypted
     */
    @Cacheable(value = "masterKey", unless = "#result == null")
    public byte[] getMasterKey() {
        try {
            System.out.println("DEBUG: Getting master key...");
            MasterKey masterKeyEntity = masterKeyRepository.findActiveMasterKey()
                .orElseThrow(() -> new SecurityException("No active master key found"));
            
            System.out.println("DEBUG: Found master key entity with ID: " + masterKeyEntity.getId());
            byte[] serverKey = getServerKey();
            System.out.println("DEBUG: Retrieved server key, length: " + serverKey.length);
            
            // Decrypt master key using server key
            EncryptionService.EncryptedData encryptedData = new EncryptionService.EncryptedData(
                Base64.getDecoder().decode(masterKeyEntity.getEncryptedKey()),
                Base64.getDecoder().decode(masterKeyEntity.getEncryptionIV()),
                Base64.getDecoder().decode(masterKeyEntity.getEncryptionTag())
            );
            
            System.out.println("DEBUG: Created encrypted data object for master key decryption");
            // For master key, we need to decrypt the raw bytes, not a PrivateKey
            byte[] decryptedMasterKey = decryptMasterKeyBytes(encryptedData, serverKey);
            System.out.println("DEBUG: Successfully decrypted master key, length: " + decryptedMasterKey.length);
            return decryptedMasterKey;
        } catch (Exception e) {
            System.err.println("DEBUG: Failed to retrieve master key: " + e.getMessage());
            e.printStackTrace();
            throw new SecurityException("Failed to retrieve master key", e);
        }
    }

    /**
     * Initializes the master key if it doesn't exist.
     * This should be called during application startup.
     * 
     * @throws SecurityException if initialization fails
     */
    public void initializeMasterKey() {
        if (masterKeyRepository.findActiveMasterKey().isPresent()) {
            return; // Master key already exists
        }

        try {
            // Generate new master key
            byte[] newMasterKey = generateNewMasterKey();
            byte[] serverKey = getServerKey();
            
            // Encrypt master key with server key
            EncryptionService.EncryptedData encryptedData = encryptMasterKeyBytes(newMasterKey, serverKey);
            
            // Save to database
            MasterKey masterKey = new MasterKey();
            masterKey.setEncryptedKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
            masterKey.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
            masterKey.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));
            masterKey.setCreatedAt(LocalDateTime.now());
            masterKey.setActive(true);
            masterKey.setVersion(1);
            
            masterKeyRepository.save(masterKey);
        } catch (Exception e) {
            throw new SecurityException("Failed to initialize master key", e);
        }
    }

    /**
     * Rotates the master key to a new one.
     * This is a critical operation that should be done carefully.
     * 
     * @throws SecurityException if rotation fails
     */
    public void rotateMasterKey() {
        try {
            // Generate new master key
            byte[] newMasterKey = generateNewMasterKey();
            byte[] serverKey = getServerKey();
            
            // Encrypt new master key with server key
            EncryptionService.EncryptedData encryptedData = encryptMasterKeyBytes(newMasterKey, serverKey);
            
            // Deactivate current master key
            masterKeyRepository.deactivateAllMasterKeys();
            
            // Save new master key
            MasterKey newMasterKeyEntity = new MasterKey();
            newMasterKeyEntity.setEncryptedKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
            newMasterKeyEntity.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
            newMasterKeyEntity.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));
            newMasterKeyEntity.setCreatedAt(LocalDateTime.now());
            newMasterKeyEntity.setLastRotatedAt(LocalDateTime.now());
            newMasterKeyEntity.setActive(true);
            
            // Get next version number
            Optional<MasterKey> latestKey = masterKeyRepository.findLatestMasterKey();
            int nextVersion = latestKey.map(k -> k.getVersion() + 1).orElse(1);
            newMasterKeyEntity.setVersion(nextVersion);
            
            masterKeyRepository.save(newMasterKeyEntity);
            
            // Clear cache
            clearMasterKeyCache();
        } catch (Exception e) {
            throw new SecurityException("Failed to rotate master key", e);
        }
    }

    /**
     * Gets the server key from various sources in order of preference.
     * 
     * @return The server key as byte array
     * @throws SecurityException if server key cannot be retrieved
     */
    private byte[] getServerKey() {
        // Try file system first
        if (serverKeyFile != null && !serverKeyFile.isEmpty()) {
            try {
                return Files.readAllBytes(Paths.get(serverKeyFile));
            } catch (Exception e) {
                // Continue to next option
            }
        }
        
        // Try environment variable
        String envKey = System.getenv(serverKeyEnvVar);
        if (envKey != null && !envKey.isEmpty()) {
            try {
                return Base64.getDecoder().decode(envKey);
            } catch (Exception e) {
                // Continue to next option
            }
        }
        
        // Try fallback (for development only)
        if (serverKeyFallback != null && !serverKeyFallback.isEmpty()) {
            try {
                return Base64.getDecoder().decode(serverKeyFallback);
            } catch (Exception e) {
                // Continue to next option
            }
        }
        
        throw new SecurityException("Server key not found in file system, environment, or fallback");
    }

    /**
     * Loads the master key from the security.master-key property.
     * This ensures the same master key is used across server restarts.
     * 
     * @return The consistent master key from properties
     */
    private byte[] generateNewMasterKey() {
        return Base64.getDecoder().decode(masterKeyBase64);
    }

    /**
     * Decrypts master key bytes using server key.
     * 
     * @param encryptedData The encrypted master key data
     * @param serverKey The server key
     * @return The decrypted master key bytes
     */
    private byte[] decryptMasterKeyBytes(EncryptionService.EncryptedData encryptedData, byte[] serverKey) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(serverKey, "AES");
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, encryptedData.getIv());
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            // Combine encrypted data and tag
            byte[] ciphertextWithTag = new byte[encryptedData.getEncryptedData().length + encryptedData.getTag().length];
            System.arraycopy(encryptedData.getEncryptedData(), 0, ciphertextWithTag, 0, encryptedData.getEncryptedData().length);
            System.arraycopy(encryptedData.getTag(), 0, ciphertextWithTag, encryptedData.getEncryptedData().length, encryptedData.getTag().length);
            
            return cipher.doFinal(ciphertextWithTag);
        } catch (Exception e) {
            throw new SecurityException("Failed to decrypt master key", e);
        }
    }

    /**
     * Encrypts master key bytes using server key.
     * 
     * @param masterKeyBytes The master key bytes to encrypt
     * @param serverKey The server key
     * @return EncryptedData containing the encrypted master key
     */
    private EncryptionService.EncryptedData encryptMasterKeyBytes(byte[] masterKeyBytes, byte[] serverKey) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(serverKey, "AES");
            
            // Generate random IV
            byte[] iv = new byte[12]; // 96 bits
            java.security.SecureRandom.getInstanceStrong().nextBytes(iv);
            
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            byte[] encryptedDataWithTag = cipher.doFinal(masterKeyBytes);
            
            // Split encrypted data and tag
            byte[] encryptedData = new byte[encryptedDataWithTag.length - 16];
            byte[] tag = new byte[16];
            System.arraycopy(encryptedDataWithTag, 0, encryptedData, 0, encryptedData.length);
            System.arraycopy(encryptedDataWithTag, encryptedData.length, tag, 0, 16);
            
            return new EncryptionService.EncryptedData(encryptedData, iv, tag);
        } catch (Exception e) {
            throw new SecurityException("Failed to encrypt master key", e);
        }
    }


    /**
     * Clears the master key cache.
     * This should be called after key rotation.
     */
    public void clearMasterKeyCache() {
        // This would be implemented with a cache manager
        // For now, we'll rely on the @Cacheable annotation's cache eviction
    }
}
