package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.util.Collection;
import org.bouncycastle.cert.jcajce.JcaCertStore;

@Service
public class CertificateSignerService {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    /**
     * Signs a certificate using the provided private key.
     * 
     * @param certBuilder The certificate builder containing the certificate data
     * @param signerPrivateKey The private key to use for signing
     * @return The signed X509Certificate
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if signing fails
     */
    public X509Certificate signCertificate(org.bouncycastle.cert.X509v3CertificateBuilder certBuilder, 
                                           PrivateKey signerPrivateKey) {
        if (certBuilder == null) {
            throw new IllegalArgumentException("Certificate builder cannot be null");
        }
        if (signerPrivateKey == null) {
            throw new IllegalArgumentException("Signer private key cannot be null");
        }

        try {
            // Create content signer
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(signerPrivateKey);

            // Build the certificate
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            // Convert to X509Certificate
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (OperatorCreationException e) {
            throw new RuntimeException("Failed to create content signer", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign certificate", e);
        }
    }

    /**
     * Verifies a certificate's signature using the issuer's public key.
     * 
     * @param certificate The certificate to verify
     * @param issuerPublicKey The issuer's public key
     * @return true if the signature is valid, false otherwise
     * @throws IllegalArgumentException if parameters are invalid
     */
    public boolean verifyCertificateSignature(X509Certificate certificate, PublicKey issuerPublicKey) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        if (issuerPublicKey == null) {
            throw new IllegalArgumentException("Issuer public key cannot be null");
        }

        try {
            certificate.verify(issuerPublicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verifies a certificate chain by checking each certificate's signature against its issuer.
     * 
     * @param certificateChain The certificate chain to verify (ordered from end-entity to root)
     * @return true if the entire chain is valid, false otherwise
     * @throws IllegalArgumentException if parameters are invalid
     */
    public boolean verifyCertificateChain(java.util.List<X509Certificate> certificateChain) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain cannot be null or empty");
        }

        try {
            // Verify each certificate in the chain
            for (int i = 0; i < certificateChain.size(); i++) {
                X509Certificate certificate = certificateChain.get(i);
                
                if (i == certificateChain.size() - 1) {
                    // Last certificate (root) should be self-signed
                    if (!verifyCertificateSignature(certificate, certificate.getPublicKey())) {
                        return false;
                    }
                } else {
                    // Verify against the next certificate in the chain (its issuer)
                    X509Certificate issuer = certificateChain.get(i + 1);
                    if (!verifyCertificateSignature(certificate, issuer.getPublicKey())) {
                        return false;
                    }
                }
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verifies a certificate's signature using a collection of potential issuer certificates.
     * 
     * @param certificate The certificate to verify
     * @param issuerCertificates Collection of potential issuer certificates
     * @return true if a valid signature is found, false otherwise
     * @throws IllegalArgumentException if parameters are invalid
     */
    public boolean verifyCertificateSignature(X509Certificate certificate, 
                                              Collection<X509Certificate> issuerCertificates) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        if (issuerCertificates == null || issuerCertificates.isEmpty()) {
            throw new IllegalArgumentException("Issuer certificates cannot be null or empty");
        }

        try {
            // Find the issuer certificate
            X509Certificate issuer = findIssuerCertificate(certificate, issuerCertificates);
            if (issuer == null) {
                return false;
            }

            return verifyCertificateSignature(certificate, issuer.getPublicKey());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Finds the issuer certificate for a given certificate from a collection.
     * 
     * @param certificate The certificate to find the issuer for
     * @param issuerCertificates Collection of potential issuer certificates
     * @return The issuer certificate, or null if not found
     */
    private X509Certificate findIssuerCertificate(X509Certificate certificate, 
                                                  Collection<X509Certificate> issuerCertificates) {
        try {
            // Create a certificate store
            JcaCertStore certStore = new JcaCertStore(issuerCertificates);

            // Create a selector for the issuer
            X509CertSelector selector = new X509CertSelector();
            selector.setSubject(certificate.getIssuerX500Principal().getName());

            // Find the issuer certificate by matching subject
            for (X509Certificate cert : issuerCertificates) {
                if (cert.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                    return cert;
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Validates that a private key is compatible with the signature algorithm.
     * 
     * @param privateKey The private key to validate
     * @return true if the key is compatible, false otherwise
     */
    public boolean isCompatiblePrivateKey(PrivateKey privateKey) {
        if (privateKey == null) {
            return false;
        }

        try {
            // Try to create a content signer with the private key
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(privateKey);
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
}
