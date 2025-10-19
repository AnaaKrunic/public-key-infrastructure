package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

/**
 * Service for initializing the key management system on application startup.
 * 
 * Security Features:
 * - Ensures master key is initialized on startup
 * - Validates key management system integrity
 * - Provides startup logging for audit purposes
 */
@Service
public class KeyInitializationService implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(KeyInitializationService.class);

    private final MasterKeyService masterKeyService;

    public KeyInitializationService(MasterKeyService masterKeyService) {
        this.masterKeyService = masterKeyService;
    }

    @Override
    public void run(String... args) throws Exception {
        logger.info("Initializing key management system...");
        
        try {
            // Initialize master key if it doesn't exist
            masterKeyService.initializeMasterKey();
            logger.info("Key management system initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize key management system", e);
            throw new RuntimeException("Key management system initialization failed", e);
        }
    }
}
