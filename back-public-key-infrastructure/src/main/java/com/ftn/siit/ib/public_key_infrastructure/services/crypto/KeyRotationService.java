package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service for managing key rotation operations.
 * 
 * Security Features:
 * - Scheduled key rotation for enhanced security
 * - Master key rotation affects all users
 * - User key rotation is isolated per user
 * - Comprehensive logging for audit purposes
 * - Transactional operations to ensure consistency
 */
@Service
@Transactional
public class KeyRotationService {

    private static final Logger logger = LoggerFactory.getLogger(KeyRotationService.class);

    private final MasterKeyService masterKeyService;
    private final UserKeyService userKeyService;
    private final UserRepository userRepository;

    public KeyRotationService(MasterKeyService masterKeyService, 
                             UserKeyService userKeyService, 
                             UserRepository userRepository) {
        this.masterKeyService = masterKeyService;
        this.userKeyService = userKeyService;
        this.userRepository = userRepository;
    }

    /**
     * Rotates the master key and all user keys.
     * This is a critical operation that should be done carefully.
     * 
     * @throws SecurityException if rotation fails
     */
    public void rotateMasterKey() {
        logger.info("Starting master key rotation at {}", LocalDateTime.now());
        
        try {
            // Rotate master key first
            masterKeyService.rotateMasterKey();
            logger.info("Master key rotated successfully");
            
            // Rotate all user keys with the new master key
            userKeyService.rotateAllUserKeys();
            logger.info("All user keys rotated successfully");
            
            logger.info("Master key rotation completed successfully at {}", LocalDateTime.now());
        } catch (Exception e) {
            logger.error("Master key rotation failed", e);
            throw new SecurityException("Master key rotation failed", e);
        }
    }

    /**
     * Rotates the user key for a specific user.
     * 
     * @param userId The user ID
     * @throws SecurityException if rotation fails
     */
    public void rotateUserKey(Long userId) {
        logger.info("Starting user key rotation for user {} at {}", userId, LocalDateTime.now());
        
        try {
            userKeyService.rotateUserKey(userId);
            logger.info("User key rotation completed successfully for user {} at {}", userId, LocalDateTime.now());
        } catch (Exception e) {
            logger.error("User key rotation failed for user {}", userId, e);
            throw new SecurityException("User key rotation failed for user " + userId, e);
        }
    }

    /**
     * Rotates user keys for all users.
     * This is typically called when the master key is rotated.
     * 
     * @throws SecurityException if rotation fails
     */
    public void rotateAllUserKeys() {
        logger.info("Starting rotation of all user keys at {}", LocalDateTime.now());
        
        try {
            userKeyService.rotateAllUserKeys();
            logger.info("All user keys rotated successfully at {}", LocalDateTime.now());
        } catch (Exception e) {
            logger.error("Rotation of all user keys failed", e);
            throw new SecurityException("Rotation of all user keys failed", e);
        }
    }

    /**
     * Scheduled master key rotation (daily at 2 AM).
     * This can be disabled by setting the cron expression to "-" in application properties.
     */
    @Scheduled(cron = "${app.security.key-rotation.master-key.cron:0 0 2 * * ?}")
    public void scheduledMasterKeyRotation() {
        logger.info("Scheduled master key rotation triggered at {}", LocalDateTime.now());
        
        try {
            rotateMasterKey();
        } catch (Exception e) {
            logger.error("Scheduled master key rotation failed", e);
            // Don't throw exception to prevent application crash
        }
    }

    /**
     * Scheduled user key rotation (weekly on Sunday at 3 AM).
     * This can be disabled by setting the cron expression to "-" in application properties.
     */
    @Scheduled(cron = "${app.security.key-rotation.user-keys.cron:0 0 3 * * SUN}")
    public void scheduledUserKeyRotation() {
        logger.info("Scheduled user key rotation triggered at {}", LocalDateTime.now());
        
        try {
            List<User> users = userRepository.findAll();
            for (User user : users) {
                try {
                    rotateUserKey(user.getId());
                } catch (Exception e) {
                    logger.error("Failed to rotate user key for user {}", user.getId(), e);
                    // Continue with other users
                }
            }
            logger.info("Scheduled user key rotation completed at {}", LocalDateTime.now());
        } catch (Exception e) {
            logger.error("Scheduled user key rotation failed", e);
            // Don't throw exception to prevent application crash
        }
    }

    /**
     * Manual key rotation for emergency situations.
     * This should be called by administrators when needed.
     * 
     * @param rotateMasterKey Whether to rotate master key
     * @param rotateUserKeys Whether to rotate user keys
     * @throws SecurityException if rotation fails
     */
    public void emergencyKeyRotation(boolean rotateMasterKey, boolean rotateUserKeys) {
        logger.warn("Emergency key rotation initiated at {} - Master: {}, User: {}", 
                   LocalDateTime.now(), rotateMasterKey, rotateUserKeys);
        
        try {
            if (rotateMasterKey) {
                rotateMasterKey();
            }
            
            if (rotateUserKeys) {
                rotateAllUserKeys();
            }
            
            logger.warn("Emergency key rotation completed successfully at {}", LocalDateTime.now());
        } catch (Exception e) {
            logger.error("Emergency key rotation failed", e);
            throw new SecurityException("Emergency key rotation failed", e);
        }
    }

    /**
     * Gets the status of key rotation for monitoring purposes.
     * 
     * @return Key rotation status information
     */
    public KeyRotationStatus getKeyRotationStatus() {
        try {
            // Check if master key exists
            boolean masterKeyExists = masterKeyService.getMasterKey() != null;
            
            // Count users with keys
            List<User> users = userRepository.findAll();
            long usersWithKeys = users.stream()
                .mapToLong(user -> userKeyService.userKeyExists(user.getId()) ? 1 : 0)
                .sum();
            
            return new KeyRotationStatus(
                masterKeyExists,
                users.size(),
                usersWithKeys,
                LocalDateTime.now()
            );
        } catch (Exception e) {
            logger.error("Failed to get key rotation status", e);
            return new KeyRotationStatus(false, 0, 0, LocalDateTime.now());
        }
    }

    /**
     * Record class for key rotation status.
     */
    public record KeyRotationStatus(
        boolean masterKeyExists,
        long totalUsers,
        long usersWithKeys,
        LocalDateTime lastChecked
    ) {}
}
