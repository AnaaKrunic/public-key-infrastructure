package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Entity representing the master encryption key used to encrypt user-specific keys.
 * The master key itself is encrypted with a server key and stored in the database.
 * 
 * Security Model:
 * - Master key is encrypted with server key (from environment/file system)
 * - User keys are encrypted with master key
 * - Private keys are encrypted with user keys
 * 
 * This creates a three-layer key hierarchy for maximum security.
 */
@Entity
@Table(name = "master_keys")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MasterKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The encrypted master key data (Base64-encoded).
     * This is encrypted using the server key.
     */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedKey;

    /**
     * The initialization vector used for encrypting the master key (Base64-encoded).
     */
    @Column(nullable = false, length = 24)
    private String encryptionIV;

    /**
     * The authentication tag for the encrypted master key (Base64-encoded).
     */
    @Column(nullable = false, length = 24)
    private String encryptionTag;

    /**
     * Timestamp when the master key was created.
     */
    @Column(nullable = false)
    private java.time.LocalDateTime createdAt;

    /**
     * Timestamp when the master key was last rotated.
     */
    private java.time.LocalDateTime lastRotatedAt;

    /**
     * Whether this is the active master key.
     * Only one master key should be active at a time.
     */
    @Column(nullable = false)
    private boolean active = true;

    /**
     * Version number for key rotation tracking.
     */
    @Column(nullable = false)
    private Integer version = 1;
}
