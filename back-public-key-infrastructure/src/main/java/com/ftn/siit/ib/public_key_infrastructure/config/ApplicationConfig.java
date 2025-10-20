package com.ftn.siit.ib.public_key_infrastructure.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Application-wide configuration properties.
 * 
 * This class provides access to configured values like CRL distribution points,
 * server URLs, and other application settings.
 */
@Configuration
public class ApplicationConfig {

    @Value("${app.server.base-url:http://localhost:8080}")
    private String serverBaseUrl;

    @Value("${app.crl.endpoint:/api/crl}")
    private String crlEndpoint;

    /**
     * Gets the full CRL Distribution Point URL.
     * 
     * This URL is embedded in issued certificates and tells clients where
     * to download the Certificate Revocation List (CRL) for validation.
     * 
     * @return Full CRL URL (e.g., "http://localhost:8080/api/crl")
     */
    public String getCrlDistributionPointUrl() {
        String baseUrl = serverBaseUrl;
        
        // Remove trailing slash from base URL if present
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        
        // Ensure endpoint starts with /
        String endpoint = crlEndpoint;
        if (!endpoint.startsWith("/")) {
            endpoint = "/" + endpoint;
        }
        
        return baseUrl + endpoint;
    }

    /**
     * Gets the configured server base URL.
     * 
     * @return Server base URL (e.g., "http://localhost:8080")
     */
    public String getServerBaseUrl() {
        return serverBaseUrl;
    }

    /**
     * Gets the CRL endpoint path.
     * 
     * @return CRL endpoint (e.g., "/api/crl")
     */
    public String getCrlEndpoint() {
        return crlEndpoint;
    }
}

