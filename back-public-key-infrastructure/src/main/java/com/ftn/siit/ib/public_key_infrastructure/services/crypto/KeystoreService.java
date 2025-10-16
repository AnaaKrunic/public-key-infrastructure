package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Service
public class KeystoreService {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String PRIVATE_KEY_ALIAS = "privatekey";
    private static final String CERTIFICATE_ALIAS = "certificate";

    /**
     * Creates a PKCS12 keystore containing a private key and a single certificate.
     * 
     * @param privateKey The private key to include
     * @param certificate The certificate to include
     * @param password The keystore password (minimum 6 characters)
     * @return The keystore as a byte array
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if keystore creation fails
     */
    public byte[] createPKCS12Keystore(PrivateKey privateKey, X509Certificate certificate, String password) {
        validateKeystoreParameters(privateKey, certificate, password);
        
        try {
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(null, null);

            // Add private key
            keystore.setKeyEntry(PRIVATE_KEY_ALIAS, privateKey, password.toCharArray(), 
                new X509Certificate[]{certificate});

            // Add certificate
            keystore.setCertificateEntry(CERTIFICATE_ALIAS, certificate);

            // Convert to byte array
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            keystore.store(outputStream, password.toCharArray());
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCS12 keystore", e);
        }
    }

    /**
     * Creates a PKCS12 keystore containing a private key and a certificate chain.
     * 
     * @param privateKey The private key to include
     * @param certificateChain The certificate chain (ordered from end-entity to root)
     * @param password The keystore password (minimum 6 characters)
     * @return The keystore as a byte array
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if keystore creation fails
     */
    public byte[] createPKCS12Keystore(PrivateKey privateKey, List<X509Certificate> certificateChain, String password) {
        validateKeystoreParameters(privateKey, certificateChain, password);
        
        try {
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(null, null);

            // Convert list to array
            X509Certificate[] certArray = certificateChain.toArray(new X509Certificate[0]);

            // Add private key with certificate chain
            keystore.setKeyEntry(PRIVATE_KEY_ALIAS, privateKey, password.toCharArray(), certArray);

            // Add the first certificate (end-entity) as the main certificate
            keystore.setCertificateEntry(CERTIFICATE_ALIAS, certificateChain.get(0));

            // Convert to byte array
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            keystore.store(outputStream, password.toCharArray());
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCS12 keystore", e);
        }
    }

    /**
     * Exports a certificate as PEM format.
     * 
     * @param certificate The certificate to export
     * @return The certificate in PEM format
     * @throws IllegalArgumentException if certificate is null
     * @throws RuntimeException if export fails
     */
    public String exportCertificateAsPEM(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        try {
            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
            pemWriter.writeObject(certificate);
            pemWriter.close();
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to export certificate as PEM", e);
        }
    }

    /**
     * Exports a private key as PEM format.
     * 
     * @param privateKey The private key to export
     * @return The private key in PEM format
     * @throws IllegalArgumentException if privateKey is null
     * @throws RuntimeException if export fails
     */
    public String exportPrivateKeyAsPEM(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }

        try {
            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
            // Write in PKCS#8 format (BEGIN PRIVATE KEY) instead of PKCS#1 (BEGIN RSA PRIVATE KEY)
            JcaPKCS8Generator pkcs8Generator = new JcaPKCS8Generator(privateKey, null);
            pemWriter.writeObject(pkcs8Generator.generate());
            pemWriter.close();
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to export private key as PEM", e);
        }
    }

    /**
     * Exports a public key as PEM format.
     * 
     * @param publicKey The public key to export
     * @return The public key in PEM format
     * @throws IllegalArgumentException if publicKey is null
     * @throws RuntimeException if export fails
     */
    public String exportPublicKeyAsPEM(java.security.PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        try {
            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
            pemWriter.writeObject(publicKey);
            pemWriter.close();
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to export public key as PEM", e);
        }
    }

    /**
     * Exports a certificate chain as PEM format.
     * 
     * @param certificateChain The certificate chain to export
     * @return The certificate chain in PEM format
     * @throws IllegalArgumentException if certificateChain is null or empty
     * @throws RuntimeException if export fails
     */
    public String exportCertificateChainAsPEM(List<X509Certificate> certificateChain) {
        if (certificateChain == null) {
            throw new IllegalArgumentException("Certificate chain cannot be null");
        }
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain cannot be empty");
        }

        try {
            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
            
            for (X509Certificate certificate : certificateChain) {
                pemWriter.writeObject(certificate);
            }
            
            pemWriter.close();
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to export certificate chain as PEM", e);
        }
    }

    /**
     * Creates a PKCS12 keystore from a certificate chain with custom aliases.
     * 
     * @param privateKey The private key to include
     * @param certificateChain The certificate chain
     * @param password The keystore password
     * @param privateKeyAlias The alias for the private key
     * @param certificateAlias The alias for the certificate
     * @return The keystore as a byte array
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if keystore creation fails
     */
    public byte[] createPKCS12Keystore(PrivateKey privateKey, List<X509Certificate> certificateChain, 
                                       String password, String privateKeyAlias, String certificateAlias) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (certificateChain == null) {
            throw new IllegalArgumentException("Certificate chain cannot be null");
        }
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain cannot be empty");
        }
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }
        if (privateKeyAlias == null || privateKeyAlias.trim().isEmpty()) {
            throw new IllegalArgumentException("Private key alias cannot be null or empty");
        }
        if (certificateAlias == null || certificateAlias.trim().isEmpty()) {
            throw new IllegalArgumentException("Certificate alias cannot be null or empty");
        }

        try {
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(null, null);

            // Convert list to array
            X509Certificate[] certArray = certificateChain.toArray(new X509Certificate[0]);

            // Add private key with certificate chain
            keystore.setKeyEntry(privateKeyAlias, privateKey, password.toCharArray(), certArray);

            // Add the first certificate (end-entity) as the main certificate
            keystore.setCertificateEntry(certificateAlias, certificateChain.get(0));

            // Convert to byte array
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            keystore.store(outputStream, password.toCharArray());
            return outputStream.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCS12 keystore", e);
        }
    }

    /**
     * Validates parameters for keystore creation with single certificate.
     */
    private void validateKeystoreParameters(PrivateKey privateKey, X509Certificate certificate, String password) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }
    }

    /**
     * Validates parameters for keystore creation with certificate chain.
     */
    private void validateKeystoreParameters(PrivateKey privateKey, List<X509Certificate> certificateChain, String password) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (certificateChain == null) {
            throw new IllegalArgumentException("Certificate chain cannot be null");
        }
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("Certificate chain cannot be empty");
        }
        if (password == null || password.length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }
    }
}
