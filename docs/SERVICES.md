# Services Documentation

This document provides detailed documentation for all services in the PKI system, including their purpose, methods, implementation status, and usage examples.

## Crypto Layer Services

The crypto layer provides low-level cryptographic operations using Bouncy Castle library.

### KeyPairGeneratorService

**Purpose**: Generates RSA key pairs with specified key sizes.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.KeyPairGeneratorService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `generateKeyPair` | `int keySize` | `KeyPair` | Generates RSA key pair with specified size (2048 or 4096 bits) |

#### Exceptions
- `IllegalArgumentException`: If key size is not 2048 or 4096 bits
- `RuntimeException`: If RSA algorithm is not available

#### Dependencies
- None

#### Usage Example
```java
@Autowired
private KeyPairGeneratorService keyPairGeneratorService;

// Generate 2048-bit RSA key pair
KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
PrivateKey privateKey = keyPair.getPrivate();
PublicKey publicKey = keyPair.getPublic();
```

---

### CertificateGeneratorService

**Purpose**: Generates X.509 certificates, builds X.500 Distinguished Names, and handles certificate extensions.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.CertificateGeneratorService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `buildX500Name` | `String cn, String o, String ou, String l, String st, String c, String e` | `X500Name` | Builds X.500 Distinguished Name from components |
| `generateSerialNumber` | None | `BigInteger` | Generates cryptographically secure serial number |
| `generateRootCertificate` | `KeyPair keyPair, X500Name subjectDN, int validityDays, List<String> keyUsage, Integer pathLength` | `X509Certificate` | Generates self-signed root certificate |
| `generateIntermediateCertificate` | `KeyPair keyPair, X500Name subjectDN, int validityDays, List<String> keyUsage, Integer pathLength, X509Certificate issuerCert, PrivateKey issuerKey` | `X509Certificate` | Generates intermediate certificate signed by issuer |
| `generateEndEntityCertificate` | `KeyPair keyPair, X500Name subjectDN, int validityDays, List<String> keyUsage, List<String> extendedKeyUsage, List<String> subjectAlternativeNames, X509Certificate issuerCert, PrivateKey issuerKey` | `X509Certificate` | Generates end-entity certificate |
| `buildKeyUsage` | `List<String> keyUsageList` | `KeyUsage` | Builds KeyUsage extension from string list |
| `buildExtendedKeyUsage` | `List<String> extendedKeyUsageList` | `ExtendedKeyUsage` | Builds ExtendedKeyUsage extension from string list |

#### Exceptions
- `IllegalArgumentException`: For invalid parameters (empty CN, invalid country codes, invalid email formats)
- `RuntimeException`: For certificate generation failures

#### Dependencies
- None (uses Bouncy Castle directly)

#### Usage Example
```java
@Autowired
private CertificateGeneratorService certificateGeneratorService;

// Build X.500 Distinguished Name
X500Name subjectDN = certificateGeneratorService.buildX500Name(
    "My Root CA",           // Common Name
    "My Organization",      // Organization
    "IT Department",        // Organizational Unit
    "Belgrade",            // Locality
    "Serbia",              // State
    "RS",                  // Country (2-letter code)
    "admin@example.com"    // Email
);

// Generate root certificate
X509Certificate rootCert = certificateGeneratorService.generateRootCertificate(
    keyPair,               // Key pair
    subjectDN,             // Subject DN
    3650,                  // Validity days (10 years)
    Arrays.asList("keyCertSign", "cRLSign"), // Key usage
    null                   // Path length (unlimited for root)
);
```

---

### CertificateSignerService

**Purpose**: Signs certificates and verifies certificate signatures.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.CertificateSignerService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `signCertificate` | `X509Certificate certificate, PrivateKey signingKey` | `X509Certificate` | Signs a certificate with the provided private key |
| `verifyCertificateSignature` | `X509Certificate certificate, PublicKey publicKey` | `boolean` | Verifies certificate signature against public key |

#### Exceptions
- `IllegalArgumentException`: For null parameters
- `RuntimeException`: For signing or verification failures

#### Dependencies
- None (uses Bouncy Castle directly)

#### Usage Example
```java
@Autowired
private CertificateSignerService certificateSignerService;

// Sign a certificate
X509Certificate signedCert = certificateSignerService.signCertificate(
    certificate,    // Certificate to sign
    privateKey      // Signing private key
);

// Verify certificate signature
boolean isValid = certificateSignerService.verifyCertificateSignature(
    certificate,    // Certificate to verify
    publicKey       // Public key to verify against
);
```

---

### EncryptionService

**Purpose**: Encrypts and decrypts private keys using AES-256-GCM encryption.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `encryptPrivateKey` | `PrivateKey privateKey, String masterKey` | `EncryptedData` | Encrypts private key with AES-256-GCM |
| `decryptPrivateKey` | `EncryptedData encryptedData, String masterKey` | `PrivateKey` | Decrypts private key from encrypted data |

#### Exceptions
- `IllegalArgumentException`: For invalid parameters (null keys, invalid master key format)
- `SecurityException`: For decryption failures (tampered data, invalid tag)

#### Dependencies
- None (uses Java Cryptography Extension)

#### Usage Example
```java
@Autowired
private EncryptionService encryptionService;

// Encrypt private key
String masterKey = "base64-encoded-256-bit-key";
EncryptedData encryptedData = encryptionService.encryptPrivateKey(
    privateKey,    // Private key to encrypt
    masterKey      // Master encryption key
);

// Decrypt private key
PrivateKey decryptedKey = encryptionService.decryptPrivateKey(
    encryptedData, // Encrypted data
    masterKey      // Master decryption key
);
```

---

### KeystoreService

**Purpose**: Creates PKCS12 keystores and exports certificates and keys in PEM format.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.KeystoreService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `createPKCS12Keystore` | `PrivateKey privateKey, X509Certificate certificate, String password` | `byte[]` | Creates PKCS12 keystore with private key and certificate |
| `createPKCS12Keystore` | `PrivateKey privateKey, List<X509Certificate> certificateChain, String password, String privateKeyAlias, String certificateAlias` | `byte[]` | Creates PKCS12 keystore with certificate chain |
| `exportCertificateAsPEM` | `X509Certificate certificate` | `String` | Exports certificate in PEM format |
| `exportCertificateChainAsPEM` | `List<X509Certificate> certificateChain` | `String` | Exports certificate chain in PEM format |
| `exportPrivateKeyAsPEM` | `PrivateKey privateKey` | `String` | Exports private key in PKCS#8 PEM format |
| `exportPublicKeyAsPEM` | `PublicKey publicKey` | `String` | Exports public key in PEM format |

#### Exceptions
- `IllegalArgumentException`: For invalid parameters (null keys, short passwords, empty certificate chains)
- `RuntimeException`: For keystore creation or export failures

#### Dependencies
- None (uses Java KeyStore and Bouncy Castle)

#### Usage Example
```java
@Autowired
private KeystoreService keystoreService;

// Create PKCS12 keystore
byte[] keystoreBytes = keystoreService.createPKCS12Keystore(
    privateKey,     // Private key
    certificate,    // Certificate
    "password123"   // Keystore password
);

// Export certificate as PEM
String pemCertificate = keystoreService.exportCertificateAsPEM(certificate);

// Export private key as PEM (PKCS#8 format)
String pemPrivateKey = keystoreService.exportPrivateKeyAsPEM(privateKey);
```

---

### CRLGeneratorService

**Purpose**: Generates Certificate Revocation Lists (CRLs) and manages certificate revocation.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.CRLGeneratorService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `generateCRL` | `X509Certificate caCertificate, PrivateKey caPrivateKey, List<BigInteger> revokedSerialNumbers, String crlDistributionPoint` | `X509CRL` | Generates CRL with revoked certificates |

#### Exceptions
- `IllegalArgumentException`: For invalid parameters (null certificates, invalid URLs, non-CA certificates)
- `RuntimeException`: For CRL generation failures

#### Dependencies
- None (uses Bouncy Castle directly)

#### Usage Example
```java
@Autowired
private CRLGeneratorService crlGeneratorService;

// Generate CRL
List<BigInteger> revokedSerials = Arrays.asList(
    BigInteger.valueOf(12345),
    BigInteger.valueOf(67890)
);

X509CRL crl = crlGeneratorService.generateCRL(
    caCertificate,                    // CA certificate
    caPrivateKey,                     // CA private key
    revokedSerials,                   // List of revoked serial numbers
    "http://crl.example.com/crl.pem"  // CRL distribution point
);
```

## Business Logic Services

The business logic layer provides high-level operations and orchestrates crypto layer services.

### ValidationService

**Purpose**: Validates certificates, certificate chains, templates, and requests.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.ValidationService`

**Status**: ✅ Fully Implemented

#### Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `validateIssuerCertificate` | `Certificate certificate` | `void` | Validates issuer certificate (not expired, not revoked, correct type) |
| `validateCertificateChain` | `List<Certificate> chain` | `void` | Validates certificate chain (terminates at root, no broken links) |
| `validateTemplateConstraints` | `CreateEndEntityCertificateDTO request, CertificateTemplate template` | `void` | Validates request against template constraints |
| `validateCertificateRequest` | `CreateEndEntityCertificateDTO request` | `void` | Validates certificate request parameters |
| `validateRevocationRequest` | `String serialNumber, User requester` | `void` | Validates revocation request permissions |

#### Exceptions
- `InvalidCertificateException`: For certificate validation failures
- `InvalidCertificateChainException`: For chain validation failures
- `TemplateConstraintViolationException`: For template constraint violations
- `ValidationException`: For general validation failures
- `UnauthorizedException`: For permission violations
- `IllegalStateException`: For invalid state operations

#### Dependencies
- `CertificateSignerService`: For signature verification
- `CertificateRepository`: For certificate lookups
- `CertificateTemplateRepository`: For template lookups

#### Usage Example
```java
@Autowired
private ValidationService validationService;

// Validate certificate
try {
    validationService.validateIssuerCertificate(certificate);
    System.out.println("Certificate is valid");
} catch (InvalidCertificateException e) {
    System.out.println("Certificate validation failed: " + e.getMessage());
}

// Validate certificate chain
try {
    validationService.validateCertificateChain(chain);
    System.out.println("Certificate chain is valid");
} catch (InvalidCertificateChainException e) {
    System.out.println("Chain validation failed: " + e.getMessage());
}
```

---

### CertificateService

**Purpose**: Manages certificate lifecycle operations.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.CertificateService`

**Status**: ⚠️ Partial Implementation

#### Implemented Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `createRootCertificate` | `CreateRootCertificateDTO dto, User admin` | `CertificateDTO` | Creates self-signed root certificate |

#### Pending Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `createIntermediateCertificate` | `CreateIntermediateCertificateDTO dto, User admin` | `CertificateDTO` | Creates intermediate certificate |
| `createEndEntityCertificate` | `CreateEndEntityCertificateDTO dto, User requester` | `CertificateDTO` | Creates end-entity certificate |
| `getCertificateBySerialNumber` | `String serialNumber, User requester` | `CertificateDTO` | Retrieves certificate by serial number |
| `listCertificates` | `CertificateType type, CertificateStatus status, Pageable pageable, User requester` | `Page<CertificateDTO>` | Lists certificates with filtering |
| `getCertificateChain` | `String serialNumber` | `CertificateChainDTO` | Gets certificate chain |
| `revokeCertificate` | `String serialNumber, RevokeCertificateDTO dto, User requester` | `CertificateDTO` | Revokes certificate |
| `downloadCertificate` | `String serialNumber, String format, String password, User requester` | `byte[]` | Downloads certificate in specified format |

#### Exceptions
- `IllegalArgumentException`: For invalid parameters
- `UnauthorizedException`: For permission violations
- `NotFoundException`: For missing certificates
- `ValidationException`: For validation failures

#### Dependencies
- `ValidationService`: For request validation
- `KeyPairGeneratorService`: For key generation
- `CertificateGeneratorService`: For certificate generation
- `EncryptionService`: For private key encryption
- `KeystoreService`: For keystore creation
- `CertificateRepository`: For data persistence

#### Usage Example
```java
@Autowired
private CertificateService certificateService;

// Create root certificate
CreateRootCertificateDTO dto = new CreateRootCertificateDTO();
dto.setSubjectCN("My Root CA");
dto.setSubjectO("My Organization");
dto.setValidityDays(3650);
dto.setKeyUsage(Arrays.asList("keyCertSign", "cRLSign"));

CertificateDTO rootCert = certificateService.createRootCertificate(dto, admin);
System.out.println("Root certificate created: " + rootCert.getSerialNumber());
```

---

### TemplateService

**Purpose**: Manages certificate templates for standardized certificate creation.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.TemplateService`

**Status**: ⏳ Skeleton Implementation

#### Methods (All throw UnsupportedOperationException)

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `createTemplate` | `CreateTemplateDTO dto, User caUser` | `TemplateDTO` | Creates certificate template |
| `updateTemplate` | `Long templateId, UpdateTemplateDTO dto, User requester` | `TemplateDTO` | Updates certificate template |
| `deleteTemplate` | `Long templateId, User requester` | `void` | Deletes certificate template |
| `listTemplates` | `Pageable pageable, User requester` | `Page<TemplateDTO>` | Lists certificate templates |
| `getTemplateById` | `Long templateId, User requester` | `TemplateDTO` | Gets template by ID |
| `listTemplatesForCA` | `Long caCertificateId, Pageable pageable` | `Page<TemplateDTO>` | Lists templates for specific CA |

#### Dependencies
- `CertificateTemplateRepository`: For data persistence
- `CertificateRepository`: For CA certificate lookups

---

### CSRService

**Purpose**: Manages Certificate Signing Request workflow.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.CSRService`

**Status**: ⏳ Skeleton Implementation with Placeholder Logic

#### Methods (Placeholder implementations)

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `createCSR` | `CreateCSRDTO dto, User requester` | `CSRDTO` | Creates CSR (placeholder) |
| `uploadCSR` | `UploadCSRDTO dto, User requester` | `CSRDTO` | Uploads CSR file (placeholder) |
| `listUserCSRs` | `User requester, Pageable pageable` | `Page<CSRDTO>` | Lists user's CSRs (placeholder) |
| `listPendingCSRs` | `User approver, Pageable pageable` | `Page<CSRDTO>` | Lists pending CSRs (placeholder) |
| `approveCSR` | `Long csrId, ApproveCSRDTO dto, User approver` | `CSRDTO` | Approves CSR (placeholder) |
| `rejectCSR` | `Long csrId, RejectCSRDTO dto, User approver` | `CSRDTO` | Rejects CSR (placeholder) |
| `getCSRById` | `Long csrId, User requester` | `CSRDTO` | Gets CSR by ID (placeholder) |

#### Dependencies
- `CertificateSigningRequestRepository`: For data persistence
- `CertificateRepository`: For certificate lookups

---

### CRLService

**Purpose**: Manages Certificate Revocation List operations.

**Location**: `com.ftn.siit.ib.public_key_infrastructure.services.CRLService`

**Status**: ⏳ Skeleton Implementation with Placeholder Logic

#### Methods (Placeholder implementations)

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `generateCRL` | `Long caCertificateId, User requester` | `byte[]` | Generates CRL (placeholder) |
| `getCRL` | `Long caCertificateId` | `byte[]` | Gets stored CRL (placeholder) |
| `updateCRL` | `Long caCertificateId, User requester` | `byte[]` | Updates CRL (placeholder) |
| `checkRevocationStatus` | `String serialNumber, Long caCertificateId` | `boolean` | Checks revocation status (placeholder) |
| `getCRLDistributionPoint` | `Long caCertificateId` | `String` | Gets CRL distribution point (placeholder) |
| `getRevokedCertificates` | `Long caCertificateId` | `List<CertificateDTO>` | Gets revoked certificates (placeholder) |
| `isCRLValid` | `Long caCertificateId` | `boolean` | Checks CRL validity (placeholder) |

#### Dependencies
- `CRLGeneratorService`: For CRL generation
- `CertificateRepository`: For certificate lookups
- `CRLRepository`: For CRL storage

## Service Dependencies

```
ValidationService
├── CertificateSignerService
├── CertificateRepository
└── CertificateTemplateRepository

CertificateService
├── ValidationService
├── KeyPairGeneratorService
├── CertificateGeneratorService
├── EncryptionService
├── KeystoreService
└── CertificateRepository

TemplateService
├── CertificateTemplateRepository
└── CertificateRepository

CSRService
├── CertificateSigningRequestRepository
└── CertificateRepository

CRLService
├── CRLGeneratorService
├── CertificateRepository
└── CRLRepository
```

## Implementation Status Summary

| Service | Status | Implementation Level |
|---------|--------|---------------------|
| KeyPairGeneratorService | ✅ Complete | 100% |
| CertificateGeneratorService | ✅ Complete | 100% |
| CertificateSignerService | ✅ Complete | 100% |
| EncryptionService | ✅ Complete | 100% |
| KeystoreService | ✅ Complete | 100% |
| CRLGeneratorService | ✅ Complete | 100% |
| ValidationService | ✅ Complete | 100% |
| CertificateService | ⚠️ Partial | 12.5% (1/8 methods) |
| TemplateService | ⏳ Skeleton | 0% (all throw UnsupportedOperationException) |
| CSRService | ⏳ Placeholder | 0% (placeholder implementations) |
| CRLService | ⏳ Placeholder | 0% (placeholder implementations) |
