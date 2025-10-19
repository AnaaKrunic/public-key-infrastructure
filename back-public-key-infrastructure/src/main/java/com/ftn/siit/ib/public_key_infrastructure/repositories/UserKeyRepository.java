package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.UserKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for managing UserKey entities.
 * Provides methods for finding user-specific keys and managing key rotation.
 */
@Repository
public interface UserKeyRepository extends JpaRepository<UserKey, Long> {

    /**
     * Finds the active user key for a specific user.
     * 
     * @param userId The user ID
     * @return Optional containing the active user key, or empty if none found
     */
    @Query("SELECT uk FROM UserKey uk WHERE uk.userId = :userId AND uk.active = true")
    Optional<UserKey> findActiveUserKeyByUserId(@Param("userId") Long userId);

    /**
     * Finds all user keys for a specific user (including inactive ones).
     * 
     * @param userId The user ID
     * @return List of user keys for the specified user
     */
    List<UserKey> findByUserIdOrderByVersionDesc(Long userId);

    /**
     * Finds the user key with the highest version for a specific user.
     * 
     * @param userId The user ID
     * @return Optional containing the latest user key, or empty if none found
     */
    @Query("SELECT uk FROM UserKey uk WHERE uk.userId = :userId ORDER BY uk.version DESC")
    Optional<UserKey> findLatestUserKeyByUserId(@Param("userId") Long userId);

    /**
     * Counts the number of active user keys for a specific user.
     * Should always be 1 in a properly configured system.
     * 
     * @param userId The user ID
     * @return Number of active user keys for the specified user
     */
    long countByUserIdAndActiveTrue(Long userId);

    /**
     * Deactivates all user keys for a specific user (used during key rotation).
     * 
     * @param userId The user ID
     */
    @Query("UPDATE UserKey uk SET uk.active = false WHERE uk.userId = :userId")
    void deactivateAllUserKeysByUserId(@Param("userId") Long userId);

    /**
     * Finds all active user keys.
     * 
     * @return List of all active user keys
     */
    @Query("SELECT uk FROM UserKey uk WHERE uk.active = true")
    List<UserKey> findAllActiveUserKeys();
}
