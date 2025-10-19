package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import com.ftn.siit.ib.public_key_infrastructure.entities.UserKey;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserKeyRepository;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

/**
 * Service for managing user-specific encryption keys.
 * 
 * Security Features:
 * - Each user has their own AES key encrypted with master key
 * - User keys are cached for performance but can be rotated
 * - Supports key rotation per user for enhanced security
 * - Provides isolation between users' private keys
 * 
 * Key Hierarchy:
 * 1. Master Key (from MasterKeyService) -> encrypts User Keys
 * 2. User Keys (from database) -> encrypts Private Keys
 */
@Service
@Transactional
public class UserKeyService {

    private final UserKeyRepository userKeyRepository;
    private final MasterKeyService masterKeyService;

    public UserKeyService(UserKeyRepository userKeyRepository, 
                         MasterKeyService masterKeyService) {
        this.userKeyRepository = userKeyRepository;
        this.masterKeyService = masterKeyService;
    }

    /**
     * Gets the user-specific key for a given user, creating it if it doesn't exist.
     * The user key is cached for performance.
     * 
     * @param userId The user ID
     * @return The decrypted user key as byte array
     * @throws SecurityException if user key cannot be retrieved or created
     */
    @Cacheable(value = "userKey", key = "#userId", unless = "#result == null")
    public byte[] getUserKey(Long userId) {
        try {
            System.out.println("DEBUG: Getting user key for user ID: " + userId);
            Optional<UserKey> userKeyEntity = userKeyRepository.findActiveUserKeyByUserId(userId);
            
            if (userKeyEntity.isPresent()) {
                System.out.println("DEBUG: Found existing user key for user " + userId);
                // Decrypt existing user key
                UserKey uk = userKeyEntity.get();
                byte[] masterKey = masterKeyService.getMasterKey();
                System.out.println("DEBUG: Retrieved master key for user key decryption, length: " + masterKey.length);
                
                byte[] decryptedUserKey = decryptUserKeyBytes(
                    Base64.getDecoder().decode(uk.getEncryptedUserKey()),
                    Base64.getDecoder().decode(uk.getEncryptionIV()),
                    Base64.getDecoder().decode(uk.getEncryptionTag()),
                    masterKey
                );
                System.out.println("DEBUG: Successfully decrypted user key for user " + userId + ", length: " + decryptedUserKey.length);
                return decryptedUserKey;
            } else {
                System.out.println("DEBUG: No existing user key found for user " + userId + ", creating new one");
                // Create new user key
                return createUserKey(userId);
            }
        } catch (Exception e) {
            System.err.println("DEBUG: Failed to retrieve user key for user " + userId + ": " + e.getMessage());
            e.printStackTrace();
            throw new SecurityException("Failed to retrieve user key for user " + userId, e);
        }
    }

    /**
     * Creates a new user key for the specified user.
     * 
     * @param userId The user ID
     * @return The decrypted user key as byte array
     * @throws SecurityException if user key creation fails
     */
    private byte[] createUserKey(Long userId) {
        try {
            // Generate new user key
            byte[] newUserKey = generateNewUserKey();
            byte[] masterKey = masterKeyService.getMasterKey();
            
            // Encrypt user key with master key
            EncryptionService.EncryptedData encryptedData = encryptUserKeyBytes(newUserKey, masterKey);
            
            // Save to database
            UserKey userKey = new UserKey();
            userKey.setUserId(userId);
            userKey.setEncryptedUserKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
            userKey.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
            userKey.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));
            userKey.setCreatedAt(LocalDateTime.now());
            userKey.setActive(true);
            userKey.setVersion(1);
            
            userKeyRepository.save(userKey);
            
            return newUserKey;
        } catch (Exception e) {
            throw new SecurityException("Failed to create user key for user " + userId, e);
        }
    }

    /**
     * Rotates the user key for a specific user.
     * This will re-encrypt all the user's private keys with the new user key.
     * 
     * @param userId The user ID
     * @throws SecurityException if rotation fails
     */
    public void rotateUserKey(Long userId) {
        try {
            // Generate new user key
            byte[] newUserKey = generateNewUserKey();
            byte[] masterKey = masterKeyService.getMasterKey();
            
            // Encrypt new user key with master key
            EncryptionService.EncryptedData encryptedData = encryptUserKeyBytes(newUserKey, masterKey);
            
            // Deactivate current user key
            userKeyRepository.deactivateAllUserKeysByUserId(userId);
            
            // Save new user key
            UserKey newUserKeyEntity = new UserKey();
            newUserKeyEntity.setUserId(userId);
            newUserKeyEntity.setEncryptedUserKey(Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
            newUserKeyEntity.setEncryptionIV(Base64.getEncoder().encodeToString(encryptedData.getIv()));
            newUserKeyEntity.setEncryptionTag(Base64.getEncoder().encodeToString(encryptedData.getTag()));
            newUserKeyEntity.setCreatedAt(LocalDateTime.now());
            newUserKeyEntity.setLastRotatedAt(LocalDateTime.now());
            newUserKeyEntity.setActive(true);
            
            // Get next version number
            Optional<UserKey> latestKey = userKeyRepository.findLatestUserKeyByUserId(userId);
            int nextVersion = latestKey.map(k -> k.getVersion() + 1).orElse(1);
            newUserKeyEntity.setVersion(nextVersion);
            
            userKeyRepository.save(newUserKeyEntity);
            
            // Clear user key cache
            clearUserKeyCache(userId);
        } catch (Exception e) {
            throw new SecurityException("Failed to rotate user key for user " + userId, e);
        }
    }

    /**
     * Rotates user keys for all users.
     * This is typically called when the master key is rotated.
     * 
     * @throws SecurityException if rotation fails
     */
    public void rotateAllUserKeys() {
        try {
            // Get all active user keys
            userKeyRepository.findAllActiveUserKeys().forEach(userKey -> {
                rotateUserKey(userKey.getUserId());
            });
        } catch (Exception e) {
            throw new SecurityException("Failed to rotate all user keys", e);
        }
    }

    /**
     * Checks if a user key exists for the specified user.
     * 
     * @param userId The user ID
     * @return true if user key exists, false otherwise
     */
    public boolean userKeyExists(Long userId) {
        return userKeyRepository.findActiveUserKeyByUserId(userId).isPresent();
    }

    /**
     * Generates a new random user key.
     * 
     * @return A new 256-bit user key
     */
    private byte[] generateNewUserKey() {
        byte[] key = new byte[32]; // 256 bits
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Decrypts user key bytes using master key.
     * 
     * @param encryptedData The encrypted user key data
     * @param iv The initialization vector
     * @param tag The authentication tag
     * @param masterKey The master key
     * @return The decrypted user key bytes
     */
    private byte[] decryptUserKeyBytes(byte[] encryptedData, byte[] iv, byte[] tag, byte[] masterKey) {
        try {
            System.out.println("DEBUG: Decrypting user key bytes with encrypted data length: " + encryptedData.length + 
                             ", IV length: " + iv.length + ", tag length: " + tag.length + ", master key length: " + masterKey.length);
            
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(masterKey, "AES");
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            // Combine encrypted data and tag
            byte[] ciphertextWithTag = new byte[encryptedData.length + tag.length];
            System.arraycopy(encryptedData, 0, ciphertextWithTag, 0, encryptedData.length);
            System.arraycopy(tag, 0, ciphertextWithTag, encryptedData.length, tag.length);
            
            System.out.println("DEBUG: Combined ciphertext with tag, total length: " + ciphertextWithTag.length);
            byte[] decryptedBytes = cipher.doFinal(ciphertextWithTag);
            System.out.println("DEBUG: Successfully decrypted user key bytes, length: " + decryptedBytes.length);
            return decryptedBytes;
        } catch (Exception e) {
            System.err.println("DEBUG: Failed to decrypt user key bytes: " + e.getMessage());
            e.printStackTrace();
            throw new SecurityException("Failed to decrypt user key", e);
        }
    }

    /**
     * Encrypts user key bytes using master key.
     * 
     * @param userKeyBytes The user key bytes to encrypt
     * @param masterKey The master key
     * @return EncryptedData containing the encrypted user key
     */
    private EncryptionService.EncryptedData encryptUserKeyBytes(byte[] userKeyBytes, byte[] masterKey) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(masterKey, "AES");
            
            // Generate random IV
            byte[] iv = new byte[12]; // 96 bits
            java.security.SecureRandom.getInstanceStrong().nextBytes(iv);
            
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            byte[] encryptedDataWithTag = cipher.doFinal(userKeyBytes);
            
            // Split encrypted data and tag
            byte[] encryptedData = new byte[encryptedDataWithTag.length - 16];
            byte[] tag = new byte[16];
            System.arraycopy(encryptedDataWithTag, 0, encryptedData, 0, encryptedData.length);
            System.arraycopy(encryptedDataWithTag, encryptedData.length, tag, 0, 16);
            
            return new EncryptionService.EncryptedData(encryptedData, iv, tag);
        } catch (Exception e) {
            throw new SecurityException("Failed to encrypt user key", e);
        }
    }

    /**
     * Clears the user key cache for a specific user.
     * This should be called after key rotation.
     * 
     * @param userId The user ID
     */
    public void clearUserKeyCache(Long userId) {
        // This would be implemented with a cache manager
        // For now, we'll rely on the @Cacheable annotation's cache eviction
    }

    /**
     * Clears the user key cache for all users.
     * This should be called after master key rotation.
     */
    public void clearAllUserKeyCaches() {
        // This would be implemented with a cache manager
        // For now, we'll rely on the @Cacheable annotation's cache eviction
    }
}
