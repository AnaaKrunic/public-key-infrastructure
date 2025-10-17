package com.ftn.siit.ib.public_key_infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Configuration for scheduled tasks in the PKI system.
 * 
 * Security Features:
 * - Enables scheduled key rotation
 * - Configurable cron expressions for different rotation schedules
 * - Automatic key rotation for enhanced security
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
    // Configuration is handled by @EnableScheduling annotation
    // Cron expressions are configured in application.properties
}
