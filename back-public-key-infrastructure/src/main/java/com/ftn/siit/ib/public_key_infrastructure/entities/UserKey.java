package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Entity representing user-specific encryption keys.
 * Each user has their own AES key that is encrypted with the master key.
 * 
 * Security Model:
 * - User keys are encrypted with master key
 * - Private keys are encrypted with user keys
 * - This provides isolation between users' private keys
 * 
 * This creates a two-layer key hierarchy per user for maximum security.
 */
@Entity
@Table(name = "user_keys")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserKey {

    @Id
    @Column(name = "user_id")
    private Long userId;

    /**
     * The encrypted user key data (Base64-encoded).
     * This is encrypted using the master key.
     */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedUserKey;

    /**
     * The initialization vector used for encrypting the user key (Base64-encoded).
     */
    @Column(nullable = false, length = 24)
    private String encryptionIV;

    /**
     * The authentication tag for the encrypted user key (Base64-encoded).
     */
    @Column(nullable = false, length = 24)
    private String encryptionTag;

    /**
     * Timestamp when the user key was created.
     */
    @Column(nullable = false)
    private java.time.LocalDateTime createdAt;

    /**
     * Timestamp when the user key was last rotated.
     */
    private java.time.LocalDateTime lastRotatedAt;

    /**
     * Whether this is the active user key.
     * Only one user key should be active per user at a time.
     */
    @Column(nullable = false)
    private boolean active = true;

    /**
     * Version number for key rotation tracking.
     */
    @Column(nullable = false)
    private Integer version = 1;

    /**
     * Reference to the user this key belongs to.
     */
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", insertable = false, updatable = false)
    private User user;
}
