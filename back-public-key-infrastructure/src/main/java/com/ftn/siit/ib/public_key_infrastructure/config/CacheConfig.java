package com.ftn.siit.ib.public_key_infrastructure.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;

/**
 * Configuration for caching in the PKI system.
 * 
 * Security Features:
 * - Caches master keys and user keys for performance
 * - Configurable cache expiration for security
 * - Memory-based caching with size limits
 */
@Configuration
@EnableCaching
public class CacheConfig {

    /**
     * Configures the cache manager for the application.
     * 
     * @return CacheManager instance
     */
    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        
        // Configure cache specifications
        cacheManager.setCaffeine(Caffeine.newBuilder()
            .maximumSize(1000)                    // Maximum number of entries
            .expireAfterWrite(Duration.ofHours(1)) // Expire after 1 hour of write
            .recordStats()                        // Enable statistics
        );
        
        return cacheManager;
    }
}
