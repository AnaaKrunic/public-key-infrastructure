package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class CertificateGeneratorService {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern COUNTRY_CODE_PATTERN = Pattern.compile("^[A-Z]{2}$");

    /**
     * Builds an X.500 Distinguished Name from individual components.
     * 
     * @param cn Common Name (required)
     * @param o Organization (optional)
     * @param ou Organizational Unit (optional)
     * @param l Locality (optional)
     * @param st State/Province (optional)
     * @param c Country (optional, must be 2-letter ISO code)
     * @param e Email Address (optional, must be valid format)
     * @return X500Name object
     * @throws IllegalArgumentException if parameters are invalid
     */
    public X500Name buildX500Name(String cn, String o, String ou, String l, String st, String c, String e) {
        if (cn == null || cn.trim().isEmpty()) {
            throw new IllegalArgumentException("Common Name (CN) is required");
        }

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, cn.trim());

        if (o != null && !o.trim().isEmpty()) {
            builder.addRDN(BCStyle.O, o.trim());
        }
        if (ou != null && !ou.trim().isEmpty()) {
            builder.addRDN(BCStyle.OU, ou.trim());
        }
        if (l != null && !l.trim().isEmpty()) {
            builder.addRDN(BCStyle.L, l.trim());
        }
        if (st != null && !st.trim().isEmpty()) {
            builder.addRDN(BCStyle.ST, st.trim());
        }
        if (c != null && !c.trim().isEmpty()) {
            String countryCode = c.trim();
            if (!COUNTRY_CODE_PATTERN.matcher(countryCode).matches() || "XX".equals(countryCode.toUpperCase())) {
                throw new IllegalArgumentException("Country code must be 2-letter uppercase ISO 3166-1 code");
            }
            builder.addRDN(BCStyle.C, countryCode.toUpperCase());
        }
        if (e != null && !e.trim().isEmpty()) {
            if (!EMAIL_PATTERN.matcher(e.trim()).matches()) {
                throw new IllegalArgumentException("Invalid email address format");
            }
            builder.addRDN(BCStyle.E, e.trim());
        }

        return builder.build();
    }

    /**
     * Generates a cryptographically secure serial number.
     * 
     * @return A positive BigInteger serial number
     */
    public BigInteger generateSerialNumber() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(128, random).abs();
    }

    /**
     * Generates a self-signed Root CA certificate.
     * 
     * @param keyPair The key pair for the certificate
     * @param subjectDN The subject distinguished name
     * @param validityDays Validity period in days (365-7300)
     * @param keyUsage List of key usage strings
     * @param pathLength Path length constraint (null for unlimited)
     * @return X509Certificate object
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if certificate generation fails
     */
    public X509Certificate generateRootCertificate(KeyPair keyPair, X500Name subjectDN, int validityDays, 
                                                   List<String> keyUsage, Integer pathLength) {
        validateRootCertificateParameters(keyPair, subjectDN, validityDays, keyUsage, pathLength);
        
        try {
            BigInteger serialNumber = generateSerialNumber();
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + (validityDays * 24L * 60 * 60 * 1000));

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectDN, serialNumber, notBefore, notAfter, subjectDN, keyPair.getPublic()
            );

            // Add Basic Constraints extension
            BasicConstraints basicConstraints = new BasicConstraints(true);
            if (pathLength != null) {
                basicConstraints = new BasicConstraints(pathLength);
            }
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

            // Add Key Usage extension
            KeyUsage keyUsageExt = buildKeyUsage(keyUsage);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsageExt);

            // Sign the certificate
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(keyPair.getPrivate());
            
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate root certificate", e);
        }
    }

    /**
     * Generates an Intermediate CA certificate.
     * 
     * @param keyPair The key pair for the certificate
     * @param subjectDN The subject distinguished name
     * @param issuerDN The issuer distinguished name
     * @param issuerPrivateKey The issuer's private key
     * @param issuerPublicKey The issuer's public key
     * @param validityDays Validity period in days (365-3650)
     * @param keyUsage List of key usage strings
     * @param pathLength Path length constraint
     * @return X509Certificate object
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if certificate generation fails
     */
    public X509Certificate generateIntermediateCertificate(KeyPair keyPair, X500Name subjectDN, X500Name issuerDN,
                                                           PrivateKey issuerPrivateKey, PublicKey issuerPublicKey,
                                                           int validityDays, List<String> keyUsage, Integer pathLength) {
        validateIntermediateCertificateParameters(keyPair, subjectDN, issuerDN, validityDays, keyUsage, pathLength);
        
        try {
            BigInteger serialNumber = generateSerialNumber();
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + (validityDays * 24L * 60 * 60 * 1000));

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerDN, serialNumber, notBefore, notAfter, subjectDN, keyPair.getPublic()
            );

            // Add Basic Constraints extension
            BasicConstraints basicConstraints = new BasicConstraints(true);
            if (pathLength != null) {
                basicConstraints = new BasicConstraints(pathLength);
            }
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

            // Add Key Usage extension
            KeyUsage keyUsageExt = buildKeyUsage(keyUsage);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsageExt);

            // Sign the certificate
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(issuerPrivateKey);
            
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate intermediate certificate", e);
        }
    }

    /**
     * Generates an End-Entity certificate.
     * 
     * @param keyPair The key pair for the certificate
     * @param subjectDN The subject distinguished name
     * @param issuerDN The issuer distinguished name
     * @param issuerPrivateKey The issuer's private key
     * @param issuerPublicKey The issuer's public key
     * @param validityDays Validity period in days (1-365)
     * @param keyUsage List of key usage strings
     * @param extendedKeyUsage List of extended key usage strings
     * @param subjectAlternativeNames List of SANs
     * @param crlDistributionPoint CRL distribution point URL
     * @return X509Certificate object
     * @throws IllegalArgumentException if parameters are invalid
     * @throws RuntimeException if certificate generation fails
     */
    public X509Certificate generateEndEntityCertificate(KeyPair keyPair, X500Name subjectDN, X500Name issuerDN,
                                                        PrivateKey issuerPrivateKey, PublicKey issuerPublicKey,
                                                        int validityDays, List<String> keyUsage, 
                                                        List<String> extendedKeyUsage, List<String> subjectAlternativeNames,
                                                        String crlDistributionPoint) {
        validateEndEntityCertificateParameters(keyPair, subjectDN, issuerDN, validityDays, keyUsage, extendedKeyUsage);
        
        try {
            BigInteger serialNumber = generateSerialNumber();
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + (validityDays * 24L * 60 * 60 * 1000));

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerDN, serialNumber, notBefore, notAfter, subjectDN, keyPair.getPublic()
            );

            // Add Basic Constraints extension (not a CA)
            BasicConstraints basicConstraints = new BasicConstraints(false);
            certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);

            // Add Key Usage extension
            KeyUsage keyUsageExt = buildKeyUsage(keyUsage);
            certBuilder.addExtension(Extension.keyUsage, true, keyUsageExt);

            // Add Extended Key Usage extension
            if (extendedKeyUsage != null && !extendedKeyUsage.isEmpty()) {
                ExtendedKeyUsage eku = buildExtendedKeyUsage(extendedKeyUsage);
                certBuilder.addExtension(Extension.extendedKeyUsage, true, eku);
            }

            // Add Subject Alternative Names extension
            if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty()) {
                GeneralName[] sanArray = new GeneralName[subjectAlternativeNames.size()];
                for (int i = 0; i < subjectAlternativeNames.size(); i++) {
                    sanArray[i] = new GeneralName(GeneralName.dNSName, subjectAlternativeNames.get(i));
                }
                GeneralNames sanList = new GeneralNames(sanArray);
                certBuilder.addExtension(Extension.subjectAlternativeName, false, sanList);
            }

            // Add CRL Distribution Points extension
            if (crlDistributionPoint != null && !crlDistributionPoint.trim().isEmpty()) {
                GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, crlDistributionPoint);
                GeneralNames generalNames = new GeneralNames(generalName);
                DistributionPointName distributionPointName = new DistributionPointName(generalNames);
                DistributionPoint distributionPoint = new DistributionPoint(distributionPointName, null, null);
                certBuilder.addExtension(Extension.cRLDistributionPoints, false, 
                    new CRLDistPoint(new DistributionPoint[]{distributionPoint}));
            }

            // Sign the certificate
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(issuerPrivateKey);
            
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate end-entity certificate", e);
        }
    }

    /**
     * Builds a KeyUsage extension from a list of usage strings.
     */
    public KeyUsage buildKeyUsage(List<String> keyUsageList) {
        if (keyUsageList == null || keyUsageList.isEmpty()) {
            throw new IllegalArgumentException("Key usage list cannot be empty");
        }

        int keyUsage = 0;
        for (String usage : keyUsageList) {
            switch (usage.toLowerCase()) {
                case "digitalsignature":
                    keyUsage |= KeyUsage.digitalSignature;
                    break;
                case "nonrepudiation":
                    keyUsage |= KeyUsage.nonRepudiation;
                    break;
                case "keyencipherment":
                    keyUsage |= KeyUsage.keyEncipherment;
                    break;
                case "dataencipherment":
                    keyUsage |= KeyUsage.dataEncipherment;
                    break;
                case "keyagreement":
                    keyUsage |= KeyUsage.keyAgreement;
                    break;
                case "keycertsign":
                    keyUsage |= KeyUsage.keyCertSign;
                    break;
                case "crlsign":
                    keyUsage |= KeyUsage.cRLSign;
                    break;
                case "encipheronly":
                    keyUsage |= KeyUsage.encipherOnly;
                    break;
                case "decipheronly":
                    keyUsage |= KeyUsage.decipherOnly;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid key usage: " + usage);
            }
        }

        return new KeyUsage(keyUsage);
    }

    /**
     * Builds an ExtendedKeyUsage extension from a list of usage strings.
     */
    public ExtendedKeyUsage buildExtendedKeyUsage(List<String> extendedKeyUsageList) {
        if (extendedKeyUsageList == null || extendedKeyUsageList.isEmpty()) {
            return null;
        }

        KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsageList.size()];
        for (int i = 0; i < extendedKeyUsageList.size(); i++) {
            String originalUsage = extendedKeyUsageList.get(i);
            String usage = originalUsage.toLowerCase();
            switch (usage) {
                case "serverauth":
                    keyPurposeIds[i] = KeyPurposeId.id_kp_serverAuth;
                    break;
                case "clientauth":
                    keyPurposeIds[i] = KeyPurposeId.id_kp_clientAuth;
                    break;
                case "codesigning":
                    keyPurposeIds[i] = KeyPurposeId.id_kp_codeSigning;
                    break;
                case "emailprotection":
                    keyPurposeIds[i] = KeyPurposeId.id_kp_emailProtection;
                    break;
                case "timestamping":
                    keyPurposeIds[i] = KeyPurposeId.id_kp_timeStamping;
                    break;
                case "ocspsigning":
                    keyPurposeIds[i] = KeyPurposeId.id_kp_OCSPSigning;
                    break;
                default:
                    throw new IllegalArgumentException("Invalid extended key usage: " + originalUsage);
            }
        }

        return new ExtendedKeyUsage(keyPurposeIds);
    }

    // Validation methods
    private void validateRootCertificateParameters(KeyPair keyPair, X500Name subjectDN, int validityDays, 
                                                  List<String> keyUsage, Integer pathLength) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair cannot be null");
        }
        if (subjectDN == null) {
            throw new IllegalArgumentException("Subject DN cannot be null");
        }
        if (validityDays < 365 || validityDays > 7300) {
            throw new IllegalArgumentException("Validity must be between 365 and 7300 days");
        }
        if (keyUsage == null || keyUsage.isEmpty()) {
            throw new IllegalArgumentException("Key usage cannot be null or empty");
        }
        if (!keyUsage.contains("keyCertSign")) {
            throw new IllegalArgumentException("Root CA must have keyCertSign usage");
        }
        if (!keyUsage.contains("cRLSign")) {
            throw new IllegalArgumentException("Root CA must have cRLSign usage");
        }
        if (pathLength != null && pathLength < 0) {
            throw new IllegalArgumentException("Path length cannot be negative");
        }
    }

    private void validateIntermediateCertificateParameters(KeyPair keyPair, X500Name subjectDN, X500Name issuerDN,
                                                          int validityDays, List<String> keyUsage, Integer pathLength) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair cannot be null");
        }
        if (subjectDN == null) {
            throw new IllegalArgumentException("Subject DN cannot be null");
        }
        if (issuerDN == null) {
            throw new IllegalArgumentException("Issuer DN cannot be null");
        }
        if (subjectDN.equals(issuerDN)) {
            throw new IllegalArgumentException("Intermediate certificate cannot be self-signed");
        }
        if (validityDays < 365 || validityDays > 3650) {
            throw new IllegalArgumentException("Validity must be between 365 and 3650 days");
        }
        if (keyUsage == null || keyUsage.isEmpty()) {
            throw new IllegalArgumentException("Key usage cannot be null or empty");
        }
        if (pathLength != null && pathLength < 0) {
            throw new IllegalArgumentException("Path length cannot be negative");
        }
    }

    private void validateEndEntityCertificateParameters(KeyPair keyPair, X500Name subjectDN, X500Name issuerDN,
                                                        int validityDays, List<String> keyUsage, List<String> extendedKeyUsage) {
        if (keyPair == null) {
            throw new IllegalArgumentException("KeyPair cannot be null");
        }
        if (subjectDN == null) {
            throw new IllegalArgumentException("Subject DN cannot be null");
        }
        if (issuerDN == null) {
            throw new IllegalArgumentException("Issuer DN cannot be null");
        }
        if (validityDays < 1 || validityDays > 365) {
            throw new IllegalArgumentException("Validity must be between 1 and 365 days");
        }
        if (keyUsage == null || keyUsage.isEmpty()) {
            throw new IllegalArgumentException("Key usage cannot be null or empty");
        }
        if (keyUsage.contains("keyCertSign")) {
            throw new IllegalArgumentException("End-entity certificate cannot have keyCertSign usage");
        }
        if (keyUsage.contains("cRLSign")) {
            throw new IllegalArgumentException("End-entity certificate cannot have cRLSign usage");
        }
    }
}
