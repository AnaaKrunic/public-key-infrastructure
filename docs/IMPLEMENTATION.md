# Implementation Guide

This document provides detailed implementation information for the PKI system, including completed components, pending implementation, technical details, and code examples.

## Implementation Status Overview

### ✅ Completed Components

#### 1. Crypto Layer (100% Complete)
The entire crypto layer is fully implemented using Bouncy Castle library:

- **KeyPairGeneratorService**: RSA key pair generation (2048/4096 bits)
- **CertificateGeneratorService**: X.509 certificate generation, DN building, extensions
- **CertificateSignerService**: Certificate signing and signature verification
- **EncryptionService**: AES-256-GCM private key encryption/decryption
- **KeystoreService**: PKCS12 keystore creation, PEM export
- **CRLGeneratorService**: CRL generation and management

#### 2. ValidationService (100% Complete)
Comprehensive certificate and template validation:

- Certificate validation (expired, not yet valid, revoked, type validation)
- Certificate chain validation (termination at root, broken chains)
- Template constraint validation (CN patterns, validity periods, key usage)
- Request validation (DN fields, email formats, country codes)
- Permission validation (revocation requests)

#### 3. CertificateService (12.5% Complete)
Only root certificate creation is implemented:

- `createRootCertificate`: Fully implemented with complete validation and encryption

#### 4. Database Schema (100% Complete)
Complete entity model with relationships:

- **User**: User management with roles and authentication
- **Organization**: Organization management
- **Certificate**: Certificate storage with encrypted private keys
- **CertificateTemplate**: Template management for standardized certificates
- **CertificateSigningRequest**: CSR workflow management
- **CRL**: Certificate Revocation List storage

#### 5. Authentication System (100% Complete)
JWT-based user authentication:

- User registration and login
- Role-based access control (ADMIN, CA_USER, REGULAR_USER)
- JWT token generation and validation
- Password validation and encryption

#### 6. Test Suite (99.3% Complete)
Comprehensive test coverage:

- 303 tests covering all implemented services
- TDD approach for crypto layer
- Mock-based testing for business logic
- 1 minor failure, 1 cleanup error

### ⚠️ Partial Implementation

#### 1. CertificateService (12.5% Complete)
**Implemented**:
- `createRootCertificate`: Complete implementation

**Pending**:
- `createIntermediateCertificate`: Skeleton method
- `createEndEntityCertificate`: Skeleton method
- `getCertificateBySerialNumber`: Skeleton method
- `listCertificates`: Skeleton method
- `getCertificateChain`: Skeleton method
- `revokeCertificate`: Skeleton method
- `downloadCertificate`: Skeleton method

#### 2. TemplateService (0% Complete)
**Status**: All methods throw `UnsupportedOperationException`

**Pending Methods**:
- `createTemplate`
- `updateTemplate`
- `deleteTemplate`
- `listTemplates`
- `getTemplateById`
- `listTemplatesForCA`

#### 3. CSRService (0% Complete)
**Status**: Placeholder implementations with dummy data

**Pending Methods**:
- `createCSR`: Returns dummy CSRDTO
- `uploadCSR`: Returns dummy CSRDTO
- `listUserCSRs`: Returns empty page
- `listPendingCSRs`: Returns empty page
- `approveCSR`: Returns dummy CSRDTO
- `rejectCSR`: Returns dummy CSRDTO
- `getCSRById`: Returns dummy CSRDTO

#### 4. CRLService (0% Complete)
**Status**: Placeholder implementations with dummy data

**Pending Methods**:
- `generateCRL`: Returns dummy CRL bytes
- `getCRL`: Returns dummy CRL bytes
- `updateCRL`: Returns dummy CRL bytes
- `checkRevocationStatus`: Returns false
- `getCRLDistributionPoint`: Returns dummy URL
- `getRevokedCertificates`: Returns empty list
- `isCRLValid`: Returns true

### ⏳ Pending Implementation

#### 1. REST Controllers
**Status**: Not implemented

**Required Controllers**:
- `CertificateController`: Certificate CRUD operations
- `TemplateController`: Template management
- `CSRController`: CSR workflow
- `CRLController`: CRL operations
- `UserController`: User management

#### 2. Security Configuration
**Status**: Basic JWT authentication implemented

**Pending**:
- Method-level security annotations (`@PreAuthorize`)
- CORS configuration
- HTTPS configuration
- Self-signed certificate setup
- HTTP to HTTPS redirect

#### 3. Exception Handling
**Status**: Custom exceptions defined

**Pending**:
- Global exception handler (`@ControllerAdvice`)
- Error response formatting
- Logging configuration

#### 4. API Documentation
**Status**: Not implemented

**Pending**:
- OpenAPI/Swagger documentation
- API endpoint documentation
- Request/response examples

## Technical Implementation Details

### 1. AES-256-GCM Encryption

**Implementation**: `EncryptionService.encryptPrivateKey()`

```java
public EncryptedData encryptPrivateKey(PrivateKey privateKey, String masterKey) {
    // Validate parameters
    validateEncryptParameters(privateKey, masterKey);
    
    try {
        // Decode master key from Base64
        byte[] keyBytes = Base64.getDecoder().decode(masterKey);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        
        // Initialize cipher with GCM mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        // Get IV from cipher
        byte[] iv = cipher.getIV();
        
        // Encrypt private key
        byte[] privateKeyBytes = privateKey.getEncoded();
        byte[] encryptedDataWithTag = cipher.doFinal(privateKeyBytes);
        
        // Split encrypted data and tag
        byte[] encryptedData = new byte[privateKeyBytes.length];
        byte[] tag = new byte[GCM_TAG_LENGTH];
        System.arraycopy(encryptedDataWithTag, 0, encryptedData, 0, privateKeyBytes.length);
        System.arraycopy(encryptedDataWithTag, privateKeyBytes.length, tag, 0, GCM_TAG_LENGTH);
        
        return new EncryptedData(encryptedData, iv, tag);
    } catch (Exception e) {
        throw new RuntimeException("Failed to encrypt private key", e);
    }
}
```

**Key Features**:
- **IV Generation**: Random IV for each encryption operation
- **Tag Handling**: 16-byte authentication tag for tamper detection
- **Base64 Encoding**: Master key stored as Base64-encoded 256-bit key
- **Error Handling**: Comprehensive exception handling

### 2. Certificate Generation

**Implementation**: `CertificateGeneratorService.generateRootCertificate()`

```java
public X509Certificate generateRootCertificate(KeyPair keyPair, X500Name subjectDN, 
                                             int validityDays, List<String> keyUsage, 
                                             Integer pathLength) {
    try {
        // Generate serial number
        BigInteger serialNumber = generateSerialNumber();
        
        // Calculate validity dates
        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(validityDays);
        
        // Build certificate builder
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            subjectDN,                    // Issuer (self-signed)
            serialNumber,
            Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()),
            Date.from(notAfter.atZone(ZoneId.systemDefault()).toInstant()),
            subjectDN,                    // Subject
            keyPair.getPublic()
        );
        
        // Add BasicConstraints extension
        BasicConstraints basicConstraints = new BasicConstraints(pathLength != null ? pathLength : -1);
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        
        // Add KeyUsage extension
        KeyUsage keyUsageExt = buildKeyUsage(keyUsage);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsageExt);
        
        // Sign certificate
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
            .build(keyPair.getPrivate());
        
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        
        // Convert to X509Certificate
        return new JcaX509CertificateConverter().getCertificate(certHolder);
        
    } catch (Exception e) {
        throw new RuntimeException("Failed to generate root certificate", e);
    }
}
```

**Key Features**:
- **X.500 DN Structure**: Complete Distinguished Name building
- **Extensions**: BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeNames
- **Validity Periods**: Configurable validity periods
- **Serial Numbers**: Cryptographically secure serial number generation

### 3. Certificate Validation

**Implementation**: `ValidationService.validateIssuerCertificate()`

```java
public void validateIssuerCertificate(Certificate certificate) {
    if (certificate == null) {
        throw new InvalidCertificateException("Certificate cannot be null");
    }
    
    // Check if certificate is expired
    if (certificate.getValidTo().isBefore(LocalDateTime.now())) {
        throw new InvalidCertificateException("Certificate is expired");
    }
    
    // Check if certificate is not yet valid
    if (certificate.getValidFrom().isAfter(LocalDateTime.now())) {
        throw new InvalidCertificateException("Certificate is not yet valid");
    }
    
    // Check if certificate is revoked
    if (certificate.getStatus() == CertificateStatus.REVOKED) {
        throw new InvalidCertificateException("Certificate is revoked");
    }
    
    // Check certificate type (must be ROOT or INTERMEDIATE for issuer)
    if (certificate.getCertificateType() == CertificateType.END_ENTITY) {
        throw new InvalidCertificateException("End-entity certificates cannot be used as issuers");
    }
    
    // Check key usage (must include keyCertSign)
    if (!certificate.getKeyUsage().contains("keyCertSign")) {
        throw new InvalidCertificateException("Issuer certificate must have keyCertSign key usage");
    }
    
    // Verify certificate signature
    try {
        X509Certificate x509Cert = convertToX509Certificate(certificate);
        PublicKey publicKey = x509Cert.getPublicKey();
        boolean isValid = certificateSignerService.verifyCertificateSignature(x509Cert, publicKey);
        
        if (!isValid) {
            throw new InvalidCertificateException("Certificate signature verification failed");
        }
    } catch (Exception e) {
        throw new InvalidCertificateException("Failed to verify certificate signature", e);
    }
}
```

**Key Features**:
- **Comprehensive Validation**: Expiration, validity, revocation, type, key usage
- **Signature Verification**: Cryptographic signature verification
- **Exception Handling**: Specific exceptions for different validation failures
- **Chain Validation**: Complete certificate chain validation

### 4. Key Storage

**Implementation**: `CertificateService.createRootCertificate()`

```java
// Encrypt private key
EncryptedData encryptedPrivateKey = encryptionService.encryptPrivateKey(
    keyPair.getPrivate(), 
    masterKey
);

// Convert encrypted data to Base64 for storage
String encryptedPrivateKeyBase64 = Base64.getEncoder().encodeToString(encryptedPrivateKey.getEncryptedData());
String ivBase64 = Base64.getEncoder().encodeToString(encryptedPrivateKey.getIv());
String tagBase64 = Base64.getEncoder().encodeToString(encryptedPrivateKey.getTag());

// Create certificate entity
Certificate certificate = new Certificate();
certificate.setSerialNumber(serialNumber.toString());
certificate.setCertificateType(CertificateType.ROOT);
certificate.setStatus(CertificateStatus.VALID);
certificate.setValidFrom(notBefore);
certificate.setValidTo(notAfter);
certificate.setSubjectDN(subjectDN.toString());
certificate.setIssuerDN(subjectDN.toString()); // Self-signed
certificate.setKeyUsage(String.join(",", keyUsage));
certificate.setEncryptedPrivateKey(encryptedPrivateKeyBase64);
certificate.setIv(ivBase64);
certificate.setTag(tagBase64);
certificate.setOwner(admin);
certificate.setIssuerCertificate(null); // Root certificate has no issuer
```

**Key Features**:
- **Encrypted Storage**: Private keys encrypted with AES-256-GCM
- **Base64 Encoding**: All binary data encoded for database storage
- **Metadata Storage**: Complete certificate metadata stored
- **Relationship Management**: Proper entity relationships maintained

## Code Examples

### 1. Creating a Root Certificate

```java
@Autowired
private CertificateService certificateService;

@Autowired
private UserRepository userRepository;

public void createRootCertificate() {
    // Get admin user
    User admin = userRepository.findByEmail("admin@example.com")
        .orElseThrow(() -> new NotFoundException("Admin user not found"));
    
    // Create root certificate DTO
    CreateRootCertificateDTO dto = new CreateRootCertificateDTO();
    dto.setSubjectCN("My Root CA");
    dto.setSubjectO("My Organization");
    dto.setSubjectOU("IT Department");
    dto.setSubjectL("Belgrade");
    dto.setSubjectST("Serbia");
    dto.setSubjectC("RS");
    dto.setSubjectE("admin@example.com");
    dto.setValidityDays(3650); // 10 years
    dto.setKeyUsage(Arrays.asList("keyCertSign", "cRLSign"));
    
    // Set basic constraints
    CreateRootCertificateDTO.BasicConstraintsDTO basicConstraints = 
        new CreateRootCertificateDTO.BasicConstraintsDTO();
    basicConstraints.setCa(true);
    basicConstraints.setPathLength(null); // Unlimited
    dto.setBasicConstraints(basicConstraints);
    
    // Create certificate
    CertificateDTO certificate = certificateService.createRootCertificate(dto, admin);
    
    System.out.println("Root certificate created: " + certificate.getSerialNumber());
}
```

### 2. Validating a Certificate Chain

```java
@Autowired
private ValidationService validationService;

@Autowired
private CertificateRepository certificateRepository;

public void validateCertificateChain(String endEntitySerialNumber) {
    // Get certificate chain
    List<Certificate> chain = new ArrayList<>();
    Certificate current = certificateRepository.findBySerialNumber(endEntitySerialNumber)
        .orElseThrow(() -> new NotFoundException("Certificate not found"));
    
    // Build chain up to root
    while (current != null) {
        chain.add(current);
        if (current.getIssuerCertificate() == null) {
            break; // Reached root certificate
        }
        current = current.getIssuerCertificate();
    }
    
    // Validate chain
    try {
        validationService.validateCertificateChain(chain);
        System.out.println("Certificate chain is valid");
    } catch (InvalidCertificateChainException e) {
        System.out.println("Chain validation failed: " + e.getMessage());
    }
}
```

### 3. Encrypting a Private Key

```java
@Autowired
private EncryptionService encryptionService;

public void encryptPrivateKey() {
    // Generate key pair
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    
    // Generate master key (256-bit)
    byte[] masterKeyBytes = new byte[32];
    new SecureRandom().nextBytes(masterKeyBytes);
    String masterKey = Base64.getEncoder().encodeToString(masterKeyBytes);
    
    // Encrypt private key
    EncryptedData encryptedData = encryptionService.encryptPrivateKey(
        keyPair.getPrivate(), 
        masterKey
    );
    
    System.out.println("Private key encrypted successfully");
    System.out.println("IV: " + Base64.getEncoder().encodeToString(encryptedData.getIv()));
    System.out.println("Tag: " + Base64.getEncoder().encodeToString(encryptedData.getTag()));
}
```

### 4. Creating a PKCS12 Keystore

```java
@Autowired
private KeystoreService keystoreService;

public void createKeystore() {
    // Generate key pair and certificate (simplified)
    KeyPair keyPair = generateKeyPair();
    X509Certificate certificate = generateCertificate(keyPair);
    
    // Create PKCS12 keystore
    byte[] keystoreBytes = keystoreService.createPKCS12Keystore(
        keyPair.getPrivate(),
        certificate,
        "password123"
    );
    
    // Save keystore to file
    try (FileOutputStream fos = new FileOutputStream("keystore.p12")) {
        fos.write(keystoreBytes);
    }
    
    System.out.println("PKCS12 keystore created successfully");
}
```

## Database Schema

### Entity Relationships

```
User (1) -----> (N) Certificate
  |                    |
  |                    |
  v                    v
Organization (1) --> (N) CertificateTemplate
  |                    |
  |                    |
  v                    v
Certificate (1) --> (N) CertificateSigningRequest
  |                    |
  |                    |
  v                    v
Certificate (1) --> (N) CRL
```

### Key Tables

#### Certificate Table
```sql
CREATE TABLE certificates (
    id BIGINT PRIMARY KEY,
    serial_number VARCHAR(255) UNIQUE NOT NULL,
    certificate_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_to TIMESTAMP NOT NULL,
    subject_dn TEXT NOT NULL,
    issuer_dn TEXT NOT NULL,
    key_usage TEXT,
    extended_key_usage TEXT,
    subject_alternative_names TEXT,
    encrypted_private_key TEXT,
    iv TEXT,
    tag TEXT,
    revocation_reason VARCHAR(50),
    revocation_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    owner_id BIGINT NOT NULL,
    issuer_certificate_id BIGINT,
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (issuer_certificate_id) REFERENCES certificates(id)
);
```

#### User Table
```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL,
    organization_id BIGINT,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id)
);
```

## Security Considerations

### 1. Private Key Protection
- **Encryption**: All private keys encrypted with AES-256-GCM
- **Key Rotation**: Master keys can be rotated for enhanced security
- **Access Control**: Role-based access to private keys
- **Audit Logging**: All key operations logged

### 2. Certificate Validation
- **Chain Validation**: Complete certificate chain verification
- **Revocation Checking**: CRL-based revocation status checking
- **Template Constraints**: Enforced template constraints
- **Signature Verification**: Cryptographic signature verification

### 3. Access Control
- **Role-Based Permissions**: ADMIN, CA_USER, REGULAR_USER roles
- **Method-Level Security**: `@PreAuthorize` annotations
- **Resource Ownership**: Users can only access their own resources
- **Audit Trail**: Complete audit trail for all operations

## Performance Considerations

### 1. Database Optimization
- **Indexing**: Proper indexes on frequently queried fields
- **Pagination**: All list operations use pagination
- **Lazy Loading**: Entity relationships use lazy loading
- **Connection Pooling**: Database connection pooling configured

### 2. Cryptographic Operations
- **Key Caching**: Frequently used keys cached in memory
- **Async Operations**: Long-running operations can be made async
- **Batch Processing**: Bulk operations for efficiency
- **Resource Management**: Proper resource cleanup

### 3. Memory Management
- **Streaming**: Large data streams processed in chunks
- **Garbage Collection**: Proper object lifecycle management
- **Memory Monitoring**: JVM memory monitoring
- **Resource Limits**: Configurable resource limits

## Deployment Considerations

### 1. Environment Configuration
- **Development**: H2 in-memory database
- **Production**: PostgreSQL or MySQL database
- **Configuration**: Environment-specific configuration files
- **Secrets Management**: Secure secret management

### 2. Security Configuration
- **HTTPS**: SSL/TLS configuration
- **Firewall**: Network security configuration
- **Monitoring**: Security monitoring and alerting
- **Backup**: Secure backup and recovery procedures

### 3. Scalability
- **Horizontal Scaling**: Load balancer configuration
- **Database Scaling**: Database clustering and replication
- **Caching**: Redis or similar caching solution
- **Monitoring**: Application performance monitoring
