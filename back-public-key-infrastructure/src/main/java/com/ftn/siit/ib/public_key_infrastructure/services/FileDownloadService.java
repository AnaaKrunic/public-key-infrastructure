package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.services.crypto.KeystoreService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Service for handling file downloads in various formats.
 * 
 * This service provides utilities for:
 * - Converting certificates between different formats (PEM, DER, PKCS#12)
 * - Generating proper HTTP headers for file downloads
 * - Validating file format parameters
 * - Creating standardized filenames
 */
@Service
public class FileDownloadService {

    private final KeystoreService keystoreService;

    public FileDownloadService(KeystoreService keystoreService) {
        this.keystoreService = keystoreService;
    }

    /**
     * Supported file formats for certificate downloads.
     */
    public enum FileFormat {
        PEM("application/x-pem-file", "pem"),
        DER("application/x-x509-ca-cert", "der"),
        PKCS12("application/x-pkcs12", "pfx"),
        PFX("application/x-pkcs12", "pfx");

        private final String contentType;
        private final String extension;

        FileFormat(String contentType, String extension) {
            this.contentType = contentType;
            this.extension = extension;
        }

        public String getContentType() {
            return contentType;
        }

        public String getExtension() {
            return extension;
        }

        public static FileFormat fromString(String format) {
            if (format == null) {
                return PEM;
            }
            
            try {
                return valueOf(format.toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Unsupported file format: " + format + 
                    ". Supported formats: " + java.util.Arrays.toString(values()));
            }
        }
    }

    /**
     * Downloads a certificate in the specified format.
     * 
     * @param certificate The certificate to download
     * @param format The desired file format
     * @param password Password for PKCS#12/PFX formats (required for these formats)
     * @param privateKey Private key for PKCS#12/PFX formats (required for these formats)
     * @param certificateChain Certificate chain for PKCS#12/PFX formats (optional)
     * @return FileDownloadResult containing the file data and metadata
     */
    public FileDownloadResult downloadCertificate(Certificate certificate, String format, 
                                                 String password, PrivateKey privateKey, 
                                                 List<X509Certificate> certificateChain) {
        FileFormat fileFormat = FileFormat.fromString(format);
        
        // Validate format-specific requirements
        if ((fileFormat == FileFormat.PKCS12 || fileFormat == FileFormat.PFX)) {
            if (password == null || password.length() < 6) {
                throw new IllegalArgumentException("Password is required for PKCS#12/PFX format and must be at least 6 characters");
            }
            if (privateKey == null) {
                throw new IllegalArgumentException("Private key is required for PKCS#12/PFX format");
            }
        }

        byte[] fileData;
        String filename = generateFilename(certificate.getSerialNumber(), fileFormat);

        switch (fileFormat) {
            case PEM:
                fileData = certificate.getCertificateData().getBytes();
                break;
            case DER:
                fileData = convertPemToDer(certificate.getCertificateData());
                break;
            case PKCS12:
            case PFX:
                if (certificateChain != null && !certificateChain.isEmpty()) {
                    fileData = keystoreService.createPKCS12Keystore(privateKey, certificateChain, password);
                } else {
                    // Single certificate
                    X509Certificate x509Cert = parseX509CertificateFromPEM(certificate.getCertificateData());
                    fileData = keystoreService.createPKCS12Keystore(privateKey, x509Cert, password);
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported format: " + fileFormat);
        }

        return new FileDownloadResult(fileData, fileFormat.getContentType(), filename);
    }

    /**
     * Creates HTTP headers for file download.
     * 
     * @param contentType The MIME type of the file
     * @param filename The filename for the download
     * @param fileSize The size of the file in bytes
     * @return HttpHeaders configured for file download
     */
    public HttpHeaders createDownloadHeaders(String contentType, String filename, long fileSize) {
        HttpHeaders headers = new HttpHeaders();
        
        // Set content type
        headers.setContentType(MediaType.parseMediaType(contentType));
        
        // Set content disposition for file download
        headers.setContentDispositionFormData("attachment", filename);
        
        // Set content length
        headers.setContentLength(fileSize);
        
        // Prevent caching of sensitive files
        headers.setCacheControl("no-cache, no-store, must-revalidate");
        headers.setPragma("no-cache");
        headers.setExpires(0);
        
        // Additional security headers
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        
        return headers;
    }

    /**
     * Generates a standardized filename for certificate downloads.
     * 
     * @param serialNumber The certificate serial number
     * @param format The file format
     * @return Generated filename
     */
    public String generateFilename(String serialNumber, FileFormat format) {
        return String.format("certificate_%s.%s", 
            sanitizeFilename(serialNumber), 
            format.getExtension());
    }

    /**
     * Generates a filename for CRL downloads.
     * 
     * @return Generated CRL filename
     */
    public String generateCrlFilename() {
        return "revoked_certs.crl";
    }

    /**
     * Converts PEM certificate data to DER format.
     * 
     * @param pemData The PEM-encoded certificate data
     * @return DER-encoded certificate data
     */
    private byte[] convertPemToDer(String pemData) {
        try {
            // Remove PEM headers and footers
            String cleanPem = pemData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64 to get DER data
            return Base64.getDecoder().decode(cleanPem);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert PEM to DER", e);
        }
    }

    /**
     * Parses X509Certificate from PEM string.
     * 
     * @param pemData The PEM-encoded certificate data
     * @return X509Certificate object
     */
    private X509Certificate parseX509CertificateFromPEM(String pemData) {
        try {
            // Remove PEM headers and footers
            String cleanPem = pemData
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
            
            // Decode Base64
            byte[] derData = Base64.getDecoder().decode(cleanPem);
            
            // Create certificate factory
            java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
            
            // Generate certificate from DER data
            return (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(derData)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse X509Certificate from PEM", e);
        }
    }

    /**
     * Sanitizes a filename by removing or replacing invalid characters.
     * 
     * @param filename The original filename
     * @return Sanitized filename safe for download
     */
    private String sanitizeFilename(String filename) {
        if (filename == null) {
            return "unknown";
        }
        
        // Replace invalid characters with underscores
        return filename.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /**
     * Result object containing file download data and metadata.
     */
    public static class FileDownloadResult {
        private final byte[] data;
        private final String contentType;
        private final String filename;

        public FileDownloadResult(byte[] data, String contentType, String filename) {
            this.data = data;
            this.contentType = contentType;
            this.filename = filename;
        }

        public byte[] getData() {
            return data;
        }

        public String getContentType() {
            return contentType;
        }

        public String getFilename() {
            return filename;
        }

        public long getSize() {
            return data != null ? data.length : 0;
        }
    }
}
