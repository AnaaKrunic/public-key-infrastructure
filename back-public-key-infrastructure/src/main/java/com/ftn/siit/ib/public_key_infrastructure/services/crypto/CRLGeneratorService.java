package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

@Service
public class CRLGeneratorService {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int CRL_VALIDITY_DAYS = 7;

    /**
     * Generates a Certificate Revocation List (CRL) for a CA certificate.
     * 
     * @param caCertificate The CA certificate that will sign the CRL
     * @param caPrivateKey The CA's private key for signing
     * @param revokedSerialNumbers List of serial numbers to revoke
     * @param crlDistributionPoint URL where the CRL will be published
     * @return X509CRLHolder containing the generated CRL
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if CRL generation fails
     */
    public X509CRLHolder generateCRL(X509Certificate caCertificate, PrivateKey caPrivateKey, 
                                     List<BigInteger> revokedSerialNumbers, String crlDistributionPoint) {
        validateGenerateCRLParameters(caCertificate, caPrivateKey, revokedSerialNumbers, crlDistributionPoint);
        
        try {
            X500Name issuerDN = X500Name.getInstance(caCertificate.getSubjectX500Principal().getEncoded());
            Date thisUpdate = new Date();
            Date nextUpdate = new Date(thisUpdate.getTime() + (CRL_VALIDITY_DAYS * 24L * 60 * 60 * 1000));

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerDN, thisUpdate);
            crlBuilder.setNextUpdate(nextUpdate);

            // Add revoked certificates
            for (BigInteger serialNumber : revokedSerialNumbers) {
                addRevokedCertificate(crlBuilder, serialNumber, thisUpdate, 0); // 0 = unspecified
            }

            // Add CRL Distribution Points extension
            addCRLDistributionPointExtension(crlBuilder, crlDistributionPoint);

            // Build the CRL
            return buildCRL(crlBuilder, caPrivateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CRL", e);
        }
    }

    /**
     * Adds a revoked certificate to the CRL builder.
     * 
     * @param crlBuilder The CRL builder
     * @param serialNumber The serial number of the revoked certificate
     * @param revocationDate The date when the certificate was revoked
     * @param revocationReason The reason for revocation (0-9)
     * @throws IllegalArgumentException if parameters are invalid
     */
    public void addRevokedCertificate(X509v2CRLBuilder crlBuilder, BigInteger serialNumber, 
                                      Date revocationDate, int revocationReason) {
        if (crlBuilder == null) {
            throw new IllegalArgumentException("CRL builder cannot be null");
        }
        if (serialNumber == null) {
            throw new IllegalArgumentException("Serial number cannot be null");
        }
        if (revocationDate == null) {
            throw new IllegalArgumentException("Revocation date cannot be null");
        }
        if (revocationReason < 0 || revocationReason > 9) {
            throw new IllegalArgumentException("Revocation reason must be between 0 and 9");
        }

        try {
            // Add the revoked certificate with reason
            crlBuilder.addCRLEntry(serialNumber, revocationDate, revocationReason);
        } catch (Exception e) {
            throw new RuntimeException("Failed to add revoked certificate to CRL", e);
        }
    }

    /**
     * Builds the final CRL from the builder.
     * 
     * @param crlBuilder The CRL builder
     * @param caPrivateKey The CA's private key for signing
     * @return X509CRLHolder containing the built CRL
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if CRL building fails
     */
    public X509CRLHolder buildCRL(X509v2CRLBuilder crlBuilder, PrivateKey caPrivateKey) {
        if (crlBuilder == null) {
            throw new IllegalArgumentException("CRL builder cannot be null");
        }
        if (caPrivateKey == null) {
            throw new IllegalArgumentException("CA private key cannot be null");
        }

        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(caPrivateKey);
            
            return crlBuilder.build(contentSigner);
        } catch (OperatorCreationException e) {
            throw new RuntimeException("Failed to create content signer for CRL", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build CRL", e);
        }
    }

    /**
     * Converts a Bouncy Castle CRL to a standard X509CRL.
     * 
     * @param crlHolder The Bouncy Castle CRL holder
     * @return X509CRL object
     * @throws RuntimeException if conversion fails
     */
    public java.security.cert.X509CRL convertToX509CRL(X509CRLHolder crlHolder) {
        if (crlHolder == null) {
            throw new IllegalArgumentException("CRL holder cannot be null");
        }

        try {
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            return converter.getCRL(crlHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert CRL to X509CRL", e);
        }
    }

    /**
     * Validates that a certificate is a valid CA certificate for CRL generation.
     * 
     * @param certificate The certificate to validate
     * @return true if the certificate can be used for CRL generation
     */
    public boolean isValidCACertificate(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }

        try {
            // Check if certificate has keyCertSign usage
            boolean[] keyUsage = certificate.getKeyUsage();
            if (keyUsage == null || !keyUsage[5]) { // keyCertSign is at index 5
                return false;
            }

            // Check if certificate is not expired
            Date now = new Date();
            if (now.before(certificate.getNotBefore()) || now.after(certificate.getNotAfter())) {
                return false;
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Gets the signature algorithm used by this service.
     * 
     * @return The signature algorithm name
     */
    public String getSignatureAlgorithm() {
        return SIGNATURE_ALGORITHM;
    }

    /**
     * Gets the default CRL validity period in days.
     * 
     * @return The CRL validity period in days
     */
    public int getCRLValidityDays() {
        return CRL_VALIDITY_DAYS;
    }

    // Private helper methods

    /**
     * Validates parameters for CRL generation.
     */
    private void validateGenerateCRLParameters(X509Certificate caCertificate, PrivateKey caPrivateKey, 
                                               List<BigInteger> revokedSerialNumbers, String crlDistributionPoint) {
        if (caCertificate == null) {
            throw new IllegalArgumentException("CA certificate cannot be null");
        }
        if (caPrivateKey == null) {
            throw new IllegalArgumentException("CA private key cannot be null");
        }
        if (revokedSerialNumbers == null) {
            throw new IllegalArgumentException("Revoked serial numbers cannot be null");
        }
        if (crlDistributionPoint == null || crlDistributionPoint.trim().isEmpty() || !isValidURL(crlDistributionPoint)) {
            throw new IllegalArgumentException("CRL distribution point must be a valid HTTP/HTTPS URL");
        }
        if (!isValidCACertificate(caCertificate)) {
            throw new IllegalArgumentException("Certificate must be a CA certificate (have keyCertSign usage)");
        }
    }

    /**
     * Validates that a string is a valid HTTP/HTTPS URL.
     */
    private boolean isValidURL(String urlString) {
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            return "http".equals(protocol) || "https".equals(protocol);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Adds CRL Distribution Points extension to the CRL builder.
     */
    private void addCRLDistributionPointExtension(X509v2CRLBuilder crlBuilder, String crlDistributionPoint) {
        try {
            GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionPoint);
            GeneralNames generalNames = new GeneralNames(generalName);
            DistributionPointName distributionPointName = new DistributionPointName(generalNames);
            DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
            
            crlBuilder.addExtension(Extension.cRLDistributionPoints, false, 
                new CRLDistPoint(new DistributionPoint[]{distributionPoint}));
        } catch (Exception e) {
            throw new RuntimeException("Failed to add CRL distribution point extension", e);
        }
    }
}
