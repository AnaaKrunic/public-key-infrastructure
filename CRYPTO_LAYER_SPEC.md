# PKI Cryptography Layer - Technical Specification

## Overview

This document provides detailed technical specifications for the cryptography layer of the PKI system, including method signatures, input/output specifications, edge cases, and expected behavior for each service.

---

## 2.1 KeyPairGeneratorService

**File:** `services/crypto/KeyPairGeneratorService.java`

**Dependencies:**
```java
import org.springframework.stereotype.Service;
import java.security.*;
```

**Service Annotation:** `@Service`

---

### Method: `generateKeyPair`

**Signature:**
```java
public KeyPair generateKeyPair(int keySize) throws IllegalArgumentException, NoSuchAlgorithmException
```

**Purpose:** Generate RSA key pair with specified key size for certificate creation

**Input Parameters:**
- `keySize` (int): RSA key size in bits
  - Valid values: 2048, 4096
  - Recommended: 2048 for Intermediate/End-Entity, 4096 for Root CA

**Output:**
- Returns: `KeyPair` object containing:
  - `PrivateKey`: RSA private key in PKCS#8 format
  - `PublicKey`: RSA public key in X.509 format

**Expected Behavior:**
1. Validate key size (must be 2048 or 4096)
2. Initialize `KeyPairGenerator` with "RSA" algorithm
3. Use `SecureRandom` for cryptographic strength
4. Generate and return KeyPair

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| Invalid key size (1024) | `keySize=1024` | `IllegalArgumentException`: "Key size must be 2048 or 4096 bits" |
| Invalid key size (3072) | `keySize=3072` | `IllegalArgumentException`: "Key size must be 2048 or 4096 bits" |
| Negative key size | `keySize=-1` | `IllegalArgumentException`: "Key size must be a positive integer" |
| Zero key size | `keySize=0` | `IllegalArgumentException`: "Key size must be a positive integer" |
| Valid 2048-bit | `keySize=2048` | Valid `KeyPair` object |
| Valid 4096-bit | `keySize=4096` | Valid `KeyPair` object |

**Implementation Example:**
```java
@Service
public class KeyPairGeneratorService {
    
    public KeyPair generateKeyPair(int keySize) {
        if (keySize <= 0) {
            throw new IllegalArgumentException("Key size must be a positive integer");
        }
        if (keySize != 2048 && keySize != 4096) {
            throw new IllegalArgumentException("Key size must be 2048 or 4096 bits");
        }
        
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize, new SecureRandom());
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not available", e);
        }
    }
}
```

**Performance Considerations:**
- 2048-bit key generation: ~100-200ms
- 4096-bit key generation: ~500-1000ms

---

## 2.2 CertificateGeneratorService

**File:** `services/crypto/CertificateGeneratorService.java`

**Dependencies:**
```java
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
```

**Service Annotation:** `@Service`

---

### Method: `buildX500Name`

**Signature:**
```java
public X500Name buildX500Name(String cn, String o, String ou, String l, 
                               String st, String c, String e) 
    throws IllegalArgumentException
```

**Purpose:** Construct X.500 Distinguished Name from individual components

**Input Parameters:**
| Parameter | Type | Required | Constraints | Description |
|-----------|------|----------|-------------|-------------|
| `cn` | String | Yes | Max 64 chars, not empty | Common Name |
| `o` | String | No | Max 64 chars | Organization |
| `ou` | String | No | Max 64 chars | Organizational Unit |
| `l` | String | No | Max 64 chars | Locality/City |
| `st` | String | No | Max 64 chars | State/Province |
| `c` | String | No | Exactly 2 letters (ISO 3166-1) | Country code |
| `e` | String | No | Valid email format | Email address |

**Output:**
- Returns: `X500Name` object representing the DN
- String representation: "CN=value,O=value,OU=value,L=value,ST=value,C=value,E=value"
- Order: CN, O, OU, L, ST, C, E (per RFC 4514)

**Expected Behavior:**
1. Validate CN is not null or empty
2. Validate country code is 2 uppercase letters if provided
3. Validate email format if provided
4. Build DN string in correct order
5. Skip null or empty components
6. Escape special characters (commas, quotes, etc.)
7. Return X500Name object

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| CN is null | `cn=null` | `IllegalArgumentException`: "Common Name (CN) is required" |
| CN is empty string | `cn=""` | `IllegalArgumentException`: "Common Name (CN) is required" |
| CN is whitespace only | `cn="   "` | `IllegalArgumentException`: "Common Name (CN) is required" |
| Country code invalid (lowercase) | `c="us"` | `IllegalArgumentException`: "Country code must be 2-letter uppercase ISO 3166-1 code" |
| Country code invalid (3 letters) | `c="USA"` | `IllegalArgumentException`: "Country code must be 2-letter uppercase ISO 3166-1 code" |
| Country code invalid (1 letter) | `c="U"` | `IllegalArgumentException`: "Country code must be 2-letter uppercase ISO 3166-1 code" |
| Invalid email format | `e="invalid"` | `IllegalArgumentException`: "Invalid email address format" |
| All optional fields null | `cn="Test", others=null` | Valid `X500Name`: "CN=Test" |
| CN with comma | `cn="Test, Inc"` | Valid `X500Name`: "CN=Test\\, Inc" (escaped) |
| CN with quotes | `cn="Test \"Corp\""` | Valid `X500Name`: "CN=Test \\\"Corp\\\"" (escaped) |
| Valid full DN | All fields valid | Valid `X500Name`: "CN=Test,O=Org,OU=Unit,L=City,ST=State,C=US,E=test@example.com" |

**Implementation Example:**
```java
public X500Name buildX500Name(String cn, String o, String ou, String l, 
                               String st, String c, String e) {
    // Validate CN
    if (cn == null || cn.trim().isEmpty()) {
        throw new IllegalArgumentException("Common Name (CN) is required");
    }
    
    // Validate country code
    if (c != null && !c.matches("^[A-Z]{2}$")) {
        throw new IllegalArgumentException("Country code must be 2-letter uppercase ISO 3166-1 code");
    }
    
    // Validate email
    if (e != null && !e.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
        throw new IllegalArgumentException("Invalid email address format");
    }
    
    // Build DN string
    StringBuilder dn = new StringBuilder("CN=").append(escapeDNValue(cn));
    if (o != null && !o.isEmpty()) dn.append(",O=").append(escapeDNValue(o));
    if (ou != null && !ou.isEmpty()) dn.append(",OU=").append(escapeDNValue(ou));
    if (l != null && !l.isEmpty()) dn.append(",L=").append(escapeDNValue(l));
    if (st != null && !st.isEmpty()) dn.append(",ST=").append(escapeDNValue(st));
    if (c != null && !c.isEmpty()) dn.append(",C=").append(c);
    if (e != null && !e.isEmpty()) dn.append(",E=").append(escapeDNValue(e));
    
    return new X500Name(dn.toString());
}

private String escapeDNValue(String value) {
    // Escape special characters per RFC 4514
    return value.replace("\\", "\\\\")
                .replace(",", "\\,")
                .replace("+", "\\+")
                .replace("\"", "\\\"")
                .replace("<", "\\<")
                .replace(">", "\\>")
                .replace(";", "\\;");
}
```

---

### Method: `generateSerialNumber`

**Signature:**
```java
public BigInteger generateSerialNumber()
```

**Purpose:** Generate cryptographically secure 128-bit serial number

**Input Parameters:** None

**Output:**
- Returns: `BigInteger` representing a positive 128-bit serial number
- Range: 1 to 2^128 - 1
- Format: Positive integer suitable for X.509 certificates

**Expected Behavior:**
1. Use `SecureRandom` for cryptographic strength
2. Generate 128-bit random number
3. Ensure number is positive (for ASN.1 encoding)
4. Return BigInteger

**Edge Cases:**
| Scenario | Expected Output |
|----------|-----------------|
| Normal generation | Positive 128-bit BigInteger |
| Negative number generated | Convert to positive using constructor |
| Serial number collision | Probability ~1 in 2^128 (negligible), database constraint catches |

**Implementation Example:**
```java
public BigInteger generateSerialNumber() {
    SecureRandom random = new SecureRandom();
    // Generate 128-bit positive number (MSB = 0)
    return new BigInteger(128, random);
}
```

---

### Method: `generateRootCertificate`

**Signature:**
```java
public X509Certificate generateRootCertificate(
    KeyPair keyPair,
    X500Name subjectDN,
    int validityDays,
    List<String> keyUsage,
    Integer pathLength
) throws Exception
```

**Purpose:** Generate self-signed Root CA certificate

**Input Parameters:**
| Parameter | Type | Required | Constraints | Description |
|-----------|------|----------|-------------|-------------|
| `keyPair` | KeyPair | Yes | RSA, 2048/4096-bit | Key pair for certificate |
| `subjectDN` | X500Name | Yes | Valid X.500 DN | Subject Distinguished Name |
| `validityDays` | int | Yes | 365-7300 days | Certificate validity period |
| `keyUsage` | List<String> | Yes | Must include "keyCertSign", "cRLSign" | Key usage extensions |
| `pathLength` | Integer | No | 0-10 or null (unlimited) | Max certificate chain depth |

**Output:**
- Returns: `X509Certificate` self-signed root certificate
- Version: X.509 v3
- Signature Algorithm: SHA256withRSA
- Issuer DN: Same as Subject DN (self-signed)
- Extensions: Basic Constraints, Key Usage, Subject Key Identifier, Authority Key Identifier

**Expected Behavior:**
1. Validate all parameters
2. Generate unique 128-bit serial number
3. Calculate validity period (now to now + validityDays)
4. Create certificate builder with subject = issuer
5. Add Basic Constraints extension (CA=true, pathLength) - CRITICAL
6. Add Key Usage extension (keyCertSign, cRLSign) - CRITICAL
7. Add Subject Key Identifier (SHA-1 hash of public key)
8. Add Authority Key Identifier (same as Subject Key Identifier for self-signed)
9. Sign with private key using SHA256withRSA
10. Convert to X509Certificate and return

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| keyPair is null | `keyPair=null` | `IllegalArgumentException`: "KeyPair cannot be null" |
| subjectDN is null | `subjectDN=null` | `IllegalArgumentException`: "Subject DN cannot be null" |
| validityDays < 365 | `validityDays=364` | `IllegalArgumentException`: "Validity must be between 365 and 7300 days" |
| validityDays > 7300 | `validityDays=7301` | `IllegalArgumentException`: "Validity must be between 365 and 7300 days" |
| keyUsage missing "keyCertSign" | `keyUsage=["cRLSign"]` | `IllegalArgumentException`: "Root CA must have keyCertSign usage" |
| keyUsage missing "cRLSign" | `keyUsage=["keyCertSign"]` | `IllegalArgumentException`: "Root CA must have cRLSign usage" |
| pathLength < 0 | `pathLength=-1` | `IllegalArgumentException`: "Path length cannot be negative" |
| pathLength = 0 | `pathLength=0` | Valid certificate with pathLength=0 (can only issue end-entity certs) |
| pathLength = null | `pathLength=null` | Valid certificate with unlimited pathLength |
| Private key not RSA | Non-RSA key | `InvalidKeyException`: "Key algorithm must be RSA" |
| Valid inputs | All valid | Valid self-signed X509Certificate |

**Implementation Example:**
```java
public X509Certificate generateRootCertificate(
    KeyPair keyPair,
    X500Name subjectDN,
    int validityDays,
    List<String> keyUsage,
    Integer pathLength
) throws Exception {
    
    // Validation
    if (keyPair == null) {
        throw new IllegalArgumentException("KeyPair cannot be null");
    }
    if (subjectDN == null) {
        throw new IllegalArgumentException("Subject DN cannot be null");
    }
    if (validityDays < 365 || validityDays > 7300) {
        throw new IllegalArgumentException("Validity must be between 365 and 7300 days");
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
    
    // Generate serial number
    BigInteger serialNumber = generateSerialNumber();
    
    // Calculate validity
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + (validityDays * 24L * 60 * 60 * 1000));
    
    // Build certificate (subject = issuer for self-signed)
    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        subjectDN,              // issuer (self-signed)
        serialNumber,
        notBefore,
        notAfter,
        subjectDN,              // subject (same as issuer)
        keyPair.getPublic()
    );
    
    // Add Basic Constraints extension (CRITICAL)
    int pathLengthValue = (pathLength != null) ? pathLength : Integer.MAX_VALUE;
    certBuilder.addExtension(
        Extension.basicConstraints, 
        true,  // critical
        new BasicConstraints(pathLengthValue)
    );
    
    // Add Key Usage extension (CRITICAL)
    certBuilder.addExtension(
        Extension.keyUsage, 
        true,  // critical
        buildKeyUsage(keyUsage)
    );
    
    // Add Subject Key Identifier
    SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
        keyPair.getPublic().getEncoded()
    );
    certBuilder.addExtension(
        Extension.subjectKeyIdentifier, 
        false,  // non-critical
        new SubjectKeyIdentifier(spki)
    );
    
    // Add Authority Key Identifier (same as Subject for self-signed)
    certBuilder.addExtension(
        Extension.authorityKeyIdentifier, 
        false,  // non-critical
        new AuthorityKeyIdentifier(spki)
    );
    
    // Sign certificate
    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC")
        .build(keyPair.getPrivate());
    
    X509CertificateHolder certHolder = certBuilder.build(signer);
    
    return new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certHolder);
}
```

---

### Method: `generateIntermediateCertificate`

**Signature:**
```java
public X509Certificate generateIntermediateCertificate(
    KeyPair keyPair,
    X500Name subjectDN,
    X500Name issuerDN,
    PrivateKey issuerPrivateKey,
    PublicKey issuerPublicKey,
    int validityDays,
    List<String> keyUsage,
    Integer pathLength
) throws Exception
```

**Purpose:** Generate Intermediate CA certificate signed by parent CA

**Input Parameters:**
| Parameter | Type | Required | Constraints | Description |
|-----------|------|----------|-------------|-------------|
| `keyPair` | KeyPair | Yes | RSA, 2048/4096-bit | New key pair for intermediate |
| `subjectDN` | X500Name | Yes | Valid X.500 DN, ≠ issuerDN | Subject DN for new cert |
| `issuerDN` | X500Name | Yes | Valid X.500 DN | Parent CA's DN |
| `issuerPrivateKey` | PrivateKey | Yes | RSA private key | Parent CA's private key |
| `issuerPublicKey` | PublicKey | Yes | RSA public key | Parent CA's public key |
| `validityDays` | int | Yes | 365-3650 days | Certificate validity |
| `keyUsage` | List<String> | Yes | Must include "keyCertSign", "cRLSign" | Key usage extensions |
| `pathLength` | Integer | No | 0-9, < parent's pathLength | Max chain depth |

**Output:**
- Returns: `X509Certificate` intermediate CA certificate
- Version: X.509 v3
- Signature Algorithm: SHA256withRSA
- Issuer DN: Different from Subject DN
- Extensions: Basic Constraints, Key Usage, Subject Key Identifier, Authority Key Identifier

**Expected Behavior:**
1. Validate all required parameters
2. Validate subjectDN ≠ issuerDN (not self-signed)
3. Validate pathLength < parent's pathLength (if applicable)
4. Generate unique serial number
5. Calculate validity period
6. Create certificate builder with subject ≠ issuer
7. Add Basic Constraints extension (CA=true, pathLength) - CRITICAL
8. Add Key Usage extension (keyCertSign, cRLSign) - CRITICAL
9. Add Subject Key Identifier (hash of new public key)
10. Add Authority Key Identifier (hash of issuer's public key)
11. Sign with issuer's private key using SHA256withRSA
12. Convert to X509Certificate and return

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| Any required param is null | `keyPair=null` | `IllegalArgumentException`: "KeyPair cannot be null" |
| validityDays < 365 | `validityDays=364` | `IllegalArgumentException`: "Validity must be between 365 and 3650 days" |
| validityDays > 3650 | `validityDays=3651` | `IllegalArgumentException`: "Validity must be between 365 and 3650 days" |
| subjectDN equals issuerDN | `subjectDN==issuerDN` | `IllegalArgumentException`: "Intermediate certificate cannot be self-signed" |
| pathLength >= parent's | `pathLength=5, parent=5` | `IllegalArgumentException`: "Path length must be less than issuer's path length" |
| keyUsage missing "keyCertSign" | `keyUsage=["cRLSign"]` | `IllegalArgumentException`: "Intermediate CA must have keyCertSign usage" |
| Issuer key algorithm not RSA | DSA key | `InvalidKeyException`: "Issuer key algorithm must be RSA" |
| Valid inputs | All valid | Valid intermediate X509Certificate |

---

### Method: `generateEndEntityCertificate`

**Signature:**
```java
public X509Certificate generateEndEntityCertificate(
    KeyPair keyPair,
    X500Name subjectDN,
    X500Name issuerDN,
    PrivateKey issuerPrivateKey,
    PublicKey issuerPublicKey,
    int validityDays,
    List<String> keyUsage,
    List<String> extendedKeyUsage,
    List<String> subjectAlternativeNames,
    String crlDistributionPoint
) throws Exception
```

**Purpose:** Generate End-Entity certificate for users/servers/devices

**Input Parameters:**
| Parameter | Type | Required | Constraints | Description |
|-----------|------|----------|-------------|-------------|
| `keyPair` | KeyPair | Yes | RSA, 2048/4096-bit | Key pair for end-entity |
| `subjectDN` | X500Name | Yes | Valid X.500 DN | Subject DN |
| `issuerDN` | X500Name | Yes | Valid X.500 DN | CA's DN |
| `issuerPrivateKey` | PrivateKey | Yes | RSA private key | CA's private key |
| `issuerPublicKey` | PublicKey | Yes | RSA public key | CA's public key |
| `validityDays` | int | Yes | 1-365 days | Certificate validity |
| `keyUsage` | List<String> | Yes | Cannot include "keyCertSign" | Key usage extensions |
| `extendedKeyUsage` | List<String> | No | Valid EKU values | Extended key usage |
| `subjectAlternativeNames` | List<String> | No | Valid DNS/IP/Email | SANs |
| `crlDistributionPoint` | String | No | Valid URL | CRL URL |

**Output:**
- Returns: `X509Certificate` end-entity certificate
- Version: X.509 v3
- Signature Algorithm: SHA256withRSA
- Extensions: Basic Constraints (CA=false), Key Usage, Extended Key Usage, SANs, Subject Key Identifier, Authority Key Identifier, CRL Distribution Points

**Expected Behavior:**
1. Validate all required parameters
2. Validate keyUsage does NOT contain "keyCertSign" or "cRLSign"
3. Generate unique serial number
4. Calculate validity period
5. Create certificate builder
6. Add Basic Constraints extension (CA=false) - CRITICAL
7. Add Key Usage extension - CRITICAL
8. Add Extended Key Usage extension (if provided)
9. Add Subject Alternative Names (if provided)
10. Add Subject Key Identifier
11. Add Authority Key Identifier
12. Add CRL Distribution Points (if provided)
13. Sign with issuer's private key
14. Convert to X509Certificate and return

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| Any required param is null | `keyPair=null` | `IllegalArgumentException`: "KeyPair cannot be null" |
| validityDays < 1 | `validityDays=0` | `IllegalArgumentException`: "Validity must be between 1 and 365 days" |
| validityDays > 365 | `validityDays=366` | `IllegalArgumentException`: "Validity must be between 1 and 365 days" |
| keyUsage contains "keyCertSign" | `keyUsage=["keyCertSign"]` | `IllegalArgumentException`: "End-entity certificate cannot have keyCertSign usage" |
| keyUsage contains "cRLSign" | `keyUsage=["cRLSign"]` | `IllegalArgumentException`: "End-entity certificate cannot have cRLSign usage" |
| Invalid SAN format | `sans=["invalid"]` | `IllegalArgumentException`: "Invalid Subject Alternative Name format" |
| CRL URL malformed | `crl="not-a-url"` | `IllegalArgumentException`: "Invalid CRL distribution point URL" |
| Empty keyUsage list | `keyUsage=[]` | `IllegalArgumentException`: "Key usage list cannot be empty" |
| Valid inputs | All valid | Valid end-entity X509Certificate |

---

### Helper Method: `buildKeyUsage`

**Signature:**
```java
private KeyUsage buildKeyUsage(List<String> keyUsageList) 
    throws IllegalArgumentException
```

**Purpose:** Convert string list to Bouncy Castle KeyUsage object

**Input Parameters:**
- `keyUsageList` (List<String>): List of key usage strings

**Valid Key Usage Values:**
| String Value | Bit Flag | Description |
|--------------|----------|-------------|
| "digitalSignature" | 0x80 | Digital signature |
| "nonRepudiation" | 0x40 | Non-repudiation |
| "keyEncipherment" | 0x20 | Key encipherment |
| "dataEncipherment" | 0x10 | Data encipherment |
| "keyAgreement" | 0x08 | Key agreement |
| "keyCertSign" | 0x04 | Certificate signing |
| "cRLSign" | 0x02 | CRL signing |
| "encipherOnly" | 0x01 | Encipher only |
| "decipherOnly" | 0x8000 | Decipher only |

**Output:**
- Returns: `KeyUsage` object with combined bit flags

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| Empty list | `[]` | `IllegalArgumentException`: "Key usage list cannot be empty" |
| Null list | `null` | `IllegalArgumentException`: "Key usage list cannot be null" |
| Invalid string | `["invalidUsage"]` | `IllegalArgumentException`: "Invalid key usage: invalidUsage" |
| Valid single usage | `["digitalSignature"]` | Valid `KeyUsage` with digitalSignature bit set |
| Valid multiple usages | `["digitalSignature", "keyEncipherment"]` | Valid `KeyUsage` with both bits set |

---

### Helper Method: `buildExtendedKeyUsage`

**Signature:**
```java
private ExtendedKeyUsage buildExtendedKeyUsage(List<String> ekuList) 
    throws IllegalArgumentException
```

**Purpose:** Convert string list to Bouncy Castle ExtendedKeyUsage object

**Input Parameters:**
- `ekuList` (List<String>): List of extended key usage strings

**Valid Extended Key Usage Values:**
| String Value | OID | Description |
|--------------|-----|-------------|
| "serverAuth" | 1.3.6.1.5.5.7.3.1 | TLS Web Server Authentication |
| "clientAuth" | 1.3.6.1.5.5.7.3.2 | TLS Web Client Authentication |
| "codeSigning" | 1.3.6.1.5.5.7.3.3 | Code Signing |
| "emailProtection" | 1.3.6.1.5.5.7.3.4 | Email Protection |
| "timeStamping" | 1.3.6.1.5.5.7.3.8 | Time Stamping |
| "ocspSigning" | 1.3.6.1.5.5.7.3.9 | OCSP Signing |

**Output:**
- Returns: `ExtendedKeyUsage` object with KeyPurposeId array
- Returns: `null` if ekuList is null or empty (EKU is optional)

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| Null list | `null` | `null` (EKU is optional) |
| Empty list | `[]` | `null` (EKU is optional) |
| Invalid string | `["invalidEKU"]` | `IllegalArgumentException`: "Invalid extended key usage: invalidEKU" |
| Valid single EKU | `["serverAuth"]` | Valid `ExtendedKeyUsage` with serverAuth |
| Valid multiple EKUs | `["serverAuth", "clientAuth"]` | Valid `ExtendedKeyUsage` with both |

---

## 2.3 CertificateSignerService

**File:** `services/crypto/CertificateSignerService.java`

**Dependencies:**
```java
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import java.security.*;
import java.security.cert.X509Certificate;
```

**Service Annotation:** `@Service`

---

### Method: `signCertificate`

**Signature:**
```java
public X509Certificate signCertificate(
    X509v3CertificateBuilder certBuilder,
    PrivateKey signerPrivateKey
) throws Exception
```

**Purpose:** Sign certificate with issuer's private key

**Input Parameters:**
| Parameter | Type | Required | Constraints | Description |
|-----------|------|----------|-------------|-------------|
| `certBuilder` | X509v3CertificateBuilder | Yes | Valid builder with extensions | Certificate builder |
| `signerPrivateKey` | PrivateKey | Yes | RSA private key | Issuer's private key |

**Output:**
- Returns: `X509Certificate` signed certificate
- Signature Algorithm: SHA256withRSA
- Provider: Bouncy Castle

**Expected Behavior:**
1. Validate parameters are not null
2. Create ContentSigner with SHA256withRSA algorithm
3. Use Bouncy Castle provider ("BC")
4. Build certificate with signature
5. Convert X509CertificateHolder to X509Certificate
6. Return signed certificate

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| certBuilder is null | `certBuilder=null` | `IllegalArgumentException`: "Certificate builder cannot be null" |
| signerPrivateKey is null | `signerPrivateKey=null` | `IllegalArgumentException`: "Signer private key cannot be null" |
| Private key not RSA | DSA key | `InvalidKeyException`: "Signer key must be RSA" |
| Private key corrupted | Invalid key | `SignatureException`: "Failed to sign certificate" |
| Valid inputs | All valid | Valid signed X509Certificate |

**Implementation Example:**
```java
@Service
public class CertificateSignerService {
    
    public X509Certificate signCertificate(
        X509v3CertificateBuilder certBuilder,
        PrivateKey signerPrivateKey
    ) throws Exception {
        
        if (certBuilder == null) {
            throw new IllegalArgumentException("Certificate builder cannot be null");
        }
        if (signerPrivateKey == null) {
            throw new IllegalArgumentException("Signer private key cannot be null");
        }
        if (!"RSA".equals(signerPrivateKey.getAlgorithm())) {
            throw new InvalidKeyException("Signer key must be RSA");
        }
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(signerPrivateKey);
        
        X509CertificateHolder certHolder = certBuilder.build(signer);
        
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);
    }
}
```

---

### Method: `verifyCertificateSignature`

**Signature:**
```java
public boolean verifyCertificateSignature(
    X509Certificate certificate,
    PublicKey issuerPublicKey
) throws IllegalArgumentException
```

**Purpose:** Verify certificate signature using issuer's public key

**Input Parameters:**
| Parameter | Type | Required | Constraints | Description |
|-----------|------|----------|-------------|-------------|
| `certificate` | X509Certificate | Yes | Valid X.509 certificate | Certificate to verify |
| `issuerPublicKey` | PublicKey | Yes | RSA public key | Issuer's public key |

**Output:**
- Returns: `true` if signature is valid
- Returns: `false` if signature is invalid or verification fails

**Expected Behavior:**
1. Validate parameters are not null
2. Call certificate.verify(issuerPublicKey)
3. Return true if verification succeeds
4. Catch exceptions and return false if verification fails

**Edge Cases:**
| Scenario | Input | Expected Output |
|----------|-------|-----------------|
| certificate is null | `certificate=null` | `IllegalArgumentException`: "Certificate cannot be null" |
| issuerPublicKey is null | `issuerPublicKey=null` | `IllegalArgumentException`: "Issuer public key cannot be null" |
| Public key algorithm mismatch | DSA key for RSA cert | `false` |
| Certificate signature corrupted | Tampered cert | `false` |
| Certificate signed by different key | Wrong public key | `false` |
| Valid signature | Correct key | `true` |

**Implementation Example:**
```java
public boolean verifyCertificateSignature(
    X509Certificate certificate,
    PublicKey issuerPublicKey
) {
    
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
        // Log the exception for debugging
        return false;
    }
}
```

---

## Summary

This technical specification provides:

1. **Complete method signatures** with all parameters and return types
2. **Detailed input/output specifications** with constraints and valid ranges
3. **Comprehensive edge case coverage** with expected behavior for each scenario
4. **Implementation examples** showing proper validation and error handling
5. **Performance considerations** where applicable
6. **Security best practices** throughout

All services follow these principles:
- **Fail-fast validation**: Check all parameters before processing
- **Clear error messages**: Descriptive exceptions for debugging
- **Cryptographic strength**: Use SecureRandom and proper key sizes
- **Standards compliance**: Follow X.509, RFC 4514, and NIST guidelines
- **Defensive programming**: Handle all edge cases gracefully

