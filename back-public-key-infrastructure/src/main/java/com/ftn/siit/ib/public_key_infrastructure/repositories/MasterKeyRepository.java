package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.MasterKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for managing MasterKey entities.
 * Provides methods for finding active master keys and managing key rotation.
 */
@Repository
public interface MasterKeyRepository extends JpaRepository<MasterKey, Long> {

    /**
     * Finds the currently active master key.
     * 
     * @return Optional containing the active master key, or empty if none found
     */
    @Query("SELECT mk FROM MasterKey mk WHERE mk.active = true ORDER BY mk.version DESC")
    Optional<MasterKey> findActiveMasterKey();

    /**
     * Finds the master key with the highest version number.
     * 
     * @return Optional containing the latest master key, or empty if none found
     */
    @Query("SELECT mk FROM MasterKey mk ORDER BY mk.version DESC")
    Optional<MasterKey> findLatestMasterKey();

    /**
     * Counts the number of active master keys.
     * Should always be 1 in a properly configured system.
     * 
     * @return Number of active master keys
     */
    long countByActiveTrue();

    /**
     * Deactivates all master keys (used during key rotation).
     */
    @Query("UPDATE MasterKey mk SET mk.active = false")
    void deactivateAllMasterKeys();
}
