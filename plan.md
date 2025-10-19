# PKI System Backend Implementation Plan

## Phase 1: Database Layer & Core Entities

### 1.1 Enums

**Role.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum Role {
    ADMIN,        // System administrator - full access
    CA_USER,      // Certificate Authority user - can issue certs for their org
    REGULAR_USER  // End user - can request certificates
}
```

**CertificateType.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum CertificateType {
    ROOT,          // Self-signed root CA certificate
    INTERMEDIATE,  // Intermediate CA certificate (signed by Root or another Intermediate)
    END_ENTITY     // End-entity certificate (leaf certificate for users/servers)
}
```

**CertificateStatus.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum CertificateStatus {
    VALID,    // Certificate is active and valid
    REVOKED   // Certificate has been revoked
}
```

**CSRStatus.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

public enum CSRStatus {
    PENDING,   // CSR awaiting CA approval
    APPROVED,  // CSR approved and certificate issued
    REJECTED   // CSR rejected by CA
}
```

### 1.2 User Entity (Updated)

**User.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String email;
    
    @Column(nullable = false)
    private String passwordHash;
    
    @Column(nullable = false)
    private String firstName;
    
    @Column(nullable = false)
    private String lastName;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.REGULAR_USER;  // Default role
    
    @ManyToOne
    @JoinColumn(name = "organization_id")
    private Organization organization;
    
    @Column(nullable = false)
    private boolean enabled = false;
    
    @Column(unique = true)
    private String activationToken;
    
    private LocalDateTime tokenExpiration;
    
    private String mfaSecret;
    
    @Column(nullable = false)
    private boolean mfaEnabled = false;
    
    // Constructors, getters, setters
}
```

### 1.3 Certificate Entity

**Certificate.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "certificates")
public class Certificate {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 64)
    private String serialNumber;  // 128-bit hex string (32 chars) or larger
    
    // ===== X.500 Subject Distinguished Name Fields =====
    @Column(nullable = false)
    private String subjectCN;  // Common Name (e.g., "www.example.com")
    
    private String subjectO;   // Organization (e.g., "Example Corp")
    private String subjectOU;  // Organizational Unit (e.g., "IT Department")
    private String subjectL;   // Locality/City (e.g., "San Francisco")
    private String subjectST;  // State/Province (e.g., "California")
    
    @Column(length = 2)
    private String subjectC;   // Country (2-letter ISO code, e.g., "US")
    
    private String subjectE;   // Email Address
    
    @Column(nullable = false, length = 500)
    private String subjectDN;  // Full DN string (e.g., "CN=www.example.com,O=Example Corp,C=US")
    
    // ===== X.500 Issuer Distinguished Name Fields =====
    @Column(nullable = false)
    private String issuerCN;
    
    private String issuerO;
    private String issuerOU;
    private String issuerL;
    private String issuerST;
    
    @Column(length = 2)
    private String issuerC;
    
    private String issuerE;
    
    @Column(nullable = false, length = 500)
    private String issuerDN;  // Full issuer DN string
    
    // ===== Validity Period =====
    @Column(nullable = false)
    private LocalDateTime validFrom;
    
    @Column(nullable = false)
    private LocalDateTime validTo;
    
    // ===== Certificate Type & Status =====
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType certificateType;
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateStatus status = CertificateStatus.VALID;
    
    // ===== Revocation Information =====
    private String revocationReason;  // X.509 standard reasons
    private LocalDateTime revocationDate;
    
    // ===== Cryptographic Material =====
    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey;  // PEM format (-----BEGIN PUBLIC KEY-----)
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPrivateKey;  // Base64-encoded AES-256-GCM ciphertext
    
    @Column(nullable = false, length = 24)
    private String encryptionIV;  // Base64-encoded 12-byte IV
    
    @Column(nullable = false, length = 24)
    private String encryptionTag;  // Base64-encoded 16-byte authentication tag
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String certificateData;  // Full X.509 certificate in PEM format
    
    // ===== X.509 Extensions =====
    @Column(length = 500)
    private String keyUsage;  // Comma-separated: "digitalSignature,keyEncipherment,keyCertSign"
    
    @Column(length = 500)
    private String extendedKeyUsage;  // Comma-separated: "serverAuth,clientAuth"
    
    @Column(length = 1000)
    private String subjectAlternativeNames;  // Comma-separated SANs
    
    @Column(length = 500)
    private String crlDistributionPoint;  // URL to CRL
    
    // ===== Relationships =====
    @ManyToOne
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;  // User who owns this certificate
    
    @ManyToOne
    @JoinColumn(name = "issuer_certificate_id")
    private Certificate issuerCertificate;  // Parent CA certificate (null for Root)
    
    @ManyToOne
    @JoinColumn(name = "template_id")
    private CertificateTemplate template;  // Template used (if any)
    
    // ===== Metadata =====
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    // Constructors, getters, setters
}
```

### 1.4 CertificateTemplate Entity

**CertificateTemplate.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_templates")
public class CertificateTemplate {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String name;  // Template name (e.g., "Web Server Template")
    
    @ManyToOne
    @JoinColumn(name = "ca_issuer_id", nullable = false)
    private User caIssuer;  // CA_USER who created this template
    
    @ManyToOne
    @JoinColumn(name = "issuer_certificate_id", nullable = false)
    private Certificate issuerCertificate;  // CA certificate to use for signing
    
    // ===== Validation Patterns (Regex) =====
    @Column(length = 500)
    private String commonNamePattern;  // Regex for CN validation (e.g., ".*\\.example\\.com")
    
    @Column(length = 500)
    private String sanPattern;  // Regex for SAN validation
    
    // ===== Certificate Constraints =====
    @Column(nullable = false)
    private Integer ttlDays;  // Maximum validity period in days
    
    // ===== Default Extensions =====
    @Column(length = 500)
    private String keyUsage;  // Default Key Usage extensions
    
    @Column(length = 500)
    private String extendedKeyUsage;  // Default Extended Key Usage
    
    // ===== Metadata =====
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
    
    // Constructors, getters, setters
}
```

### 1.5 CertificateSigningRequest Entity

**CertificateSigningRequest.java**

```java
package com.ftn.siit.ib.public_key_infrastructure.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_signing_requests")
public class CertificateSigningRequest {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // ===== CSR Data =====
    @Column(nullable = false, columnDefinition = "TEXT")
    private String csrData;  // PEM format CSR (-----BEGIN CERTIFICATE REQUEST-----)
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CSRStatus status = CSRStatus.PENDING;
    
    // ===== Requester Information =====
    @ManyToOne
    @JoinColumn(name = "requester_id", nullable = false)
    private User requester;  // User who submitted the CSR
    
    // ===== CA Selection =====
    @ManyToOne
    @JoinColumn(name = "selected_ca_id", nullable = false)
    private Certificate selectedCA;  // CA certificate to sign this CSR
    
    @ManyToOne
    @JoinColumn(name = "template_id")
    private CertificateTemplate selectedTemplate;  // Optional template for validation
    
    // ===== Subject DN Fields (extracted from CSR) =====
    @Column(nullable = false)
    private String subjectCN;
    
    private String subjectO;
    private String subjectOU;
    
    @Column(length = 2)
    private String subjectC;
    
    private String subjectE;
    
    // ===== Requested Extensions =====
    @Column(columnDefinition = "TEXT")
    private String requestedExtensions;  // JSON format: {"keyUsage": [...], "extendedKeyUsage": [...]}
    
    // ===== Processing Information =====
    private String rejectionReason;  // Reason if status = REJECTED
    
    @OneToOne
    @JoinColumn(name = "issued_certificate_id")
    private Certificate issuedCertificate;  // Certificate created when approved
    
    @ManyToOne
    @JoinColumn(name = "processed_by_id")
    private User processedBy;  // CA_USER or ADMIN who processed this CSR
    
    // ===== Timestamps =====
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    private LocalDateTime processedAt;  // When approved/rejected
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
    
    // Constructors, getters, setters
}
```

### 1.6 Repositories

Create JPA repositories for all entities in `repositories/`:

- `CertificateRepository.java` with custom queries (findBySerialNumber, findByOwner, findByStatus, findByIssuerCertificate)
- `CertificateTemplateRepository.java`
- `CertificateSigningRequestRepository.java`

## Phase 2: Cryptography Layer

Create services in `services/crypto/`:

### 2.1 KeyPairGeneratorService

- Generate RSA key pairs (2048/4096 bits)
- Return KeyPair objects for certificate generation

### 2.2 CertificateGeneratorService

- Use Bouncy Castle (add dependency to pom.xml: bcpkix-jdk18on v1.78+)
- Generate X.509 v3 certificates with extensions:
- Basic Constraints (CA flag, path length)
- Key Usage (keyCertSign, digitalSignature, keyEncipherment, etc.)
- Extended Key Usage (serverAuth, clientAuth, etc.)
- Subject Alternative Names
- CRL Distribution Points
- Support for Root, Intermediate, and End-Entity certificates
- Proper X.500 DN construction using Bouncy Castle X500Name

### 2.3 CertificateSignerService

- Sign certificates with issuer's private key
- Support SHA256withRSA signature algorithm
- Validate issuer certificate before signing

### 2.4 EncryptionService

**Encryption Architecture:**

Private keys are encrypted using AES-256-GCM with the following approach:

1. **Master Key (KEK - Key Encryption Key):**

   - Single master key stored in `application.properties` for development
   - Base64-encoded 256-bit key: `app.encryption.master-key=<base64>`
   - Production: use environment variable or external secret manager
   - Generate using: `SecureRandom` with 32 bytes

2. **Encryption Process:**
   ```
   Input: Private Key (PKCS8 PEM format)
   ↓
   Convert to byte array
   ↓
   Generate random 12-byte IV (GCM standard)
   ↓
   Encrypt with AES-256-GCM using master key
   ↓
   Output: Ciphertext + 16-byte Authentication Tag + IV
   ```

3. **Storage in Database:**

   - `encryptedPrivateKey`: Base64-encoded ciphertext (TEXT column)
   - `encryptionIV`: Base64-encoded IV (VARCHAR(24))
   - `encryptionTag`: Base64-encoded authentication tag (VARCHAR(24))

4. **Decryption Process:**
   ```
   Input: encryptedPrivateKey + IV + Tag
   ↓
   Decode from Base64
   ↓
   Decrypt with AES-256-GCM using master key + IV
   ↓
   Verify authentication tag (GCM provides AEAD)
   ↓
   Output: Private Key in PKCS8 format
   ```

5. **Implementation Details:**

   - Use `javax.crypto.Cipher` with "AES/GCM/NoPadding"
   - Use `javax.crypto.spec.GCMParameterSpec` with 128-bit tag length
   - Use `java.security.SecureRandom` for IV generation
   - Never reuse IVs (generate new IV for each encryption)
   - Handle `AEADBadTagException` for tampered data

**Service Methods:**

```java
public EncryptedData encryptPrivateKey(PrivateKey privateKey, String masterKey)
public PrivateKey decryptPrivateKey(String encryptedData, String iv, String tag, String masterKey)
public String generateMasterKey() // For initial setup
```

### 2.5 KeystoreService

- Generate PKCS12 keystores with certificate chain and private key
- Support password protection
- Export certificates in PEM format

### 2.6 CRLGeneratorService

- Generate X.509 CRL (Certificate Revocation List)
- Include revoked certificates with serial numbers and revocation dates
- Sign CRL with CA's private key
- Support CRL versioning and next update timestamps

## Phase 3: Business Logic Layer

Create services in `services/`:

### 3.1 CertificateService

Core certificate operations:

- `createRootCertificate()` - ADMIN only, self-signed
- `createIntermediateCertificate()` - ADMIN only, signed by Root/Intermediate
- `createEndEntityCertificate()` - ADMIN/CA_USER, signed by CA certificate
- `getCertificateBySerialNumber()` - role-based access
- `listCertificates()` - filtered by role (ADMIN sees all, CA_USER sees chain, REGULAR_USER sees own)
- `getCertificateChain()` - build chain from end-entity to root
- `revokeCertificate()` - validate requester permissions, update status
- `downloadCertificate()` - generate PKCS12 keystore with decrypted private key
- `validateCertificate()` - check validity period, revocation status, chain integrity

### 3.2 ValidationService

Certificate validation logic:

- `validateIssuerCertificate()` - check validity, revocation, keyCertSign usage
- `validateCertificateChain()` - verify entire chain to root
- `validateTemplateConstraints()` - check CN/SAN patterns, TTL limits
- `validateCertificateRequest()` - validate CSR or certificate creation request

### 3.3 CSRService

CSR handling:

- `createCSR()` - autogenerate with key pair creation
- `uploadCSR()` - parse external PEM CSR
- `listUserCSRs()` - for REGULAR_USER
- `listPendingCSRs()` - for CA_USER (filtered by organization)
- `approveCSR()` - validate, issue certificate, link to CSR
- `rejectCSR()` - update status with reason

### 3.4 TemplateService

Template management:

- `createTemplate()` - CA_USER only
- `updateTemplate()` - template owner only
- `deleteTemplate()` - template owner or ADMIN
- `listTemplates()` - CA_USER's templates
- `validateAgainstTemplate()` - check certificate request against template rules

### 3.5 CRLService

Revocation list management:

- `generateCRL()` - for specific CA certificate
- `getCRL()` - public endpoint, return DER format
- `updateCRL()` - regenerate when certificate revoked
- `checkRevocationStatus()` - verify if certificate is revoked

### 3.6 Update UserService

Add role management:

- `createCAUser()` - ADMIN only, assign CA_USER role
- `getUserRole()` - helper for authorization
- `checkOrganizationAccess()` - verify user can access certificate/CA

## Phase 4: DTOs

Create DTOs in `dtos/`:

### 4.1 Certificate DTOs

- `CreateRootCertificateDTO` - subject DN, validity, key size, extensions
- `CreateIntermediateCertificateDTO` - issuer ID + root DTO fields
- `CreateEndEntityCertificateDTO` - issuer ID, template ID, subject DN, extensions
- `CertificateDTO` - full certificate details for responses
- `RevokeCertificateDTO` - revocation reason enum
- `CertificateChainDTO` - list of certificates in chain

### 4.2 CSR DTOs

- `CreateCSRDTO` - autogenerate with subject DN, selected CA, template, key size
- `UploadCSRDTO` - CSR file data, selected CA, template
- `CSRDTO` - CSR details for responses
- `ApproveCSRDTO` - validity days, template, additional extensions
- `RejectCSRDTO` - rejection reason

### 4.3 Template DTOs

- `CreateTemplateDTO` - name, issuer cert ID, patterns, TTL, extensions
- `UpdateTemplateDTO` - same as create
- `TemplateDTO` - template details for responses

### 4.4 User DTOs

- `CreateCAUserDTO` - email, password, name, organization
- Update `UserRegistrationDTO` if needed

## Phase 5: REST API Controllers

Create controllers in `controllers/`:

### 5.1 CertificateController

**Base Path:** `/api/certificates`

---

#### POST /api/certificates/root

**Description:** Create a self-signed Root CA certificate

**Authorization:** `@PreAuthorize("hasRole('ADMIN')")`

**Request Body:**

```json
{
  "subjectCN": "Root CA",
  "subjectO": "Example Organization",
  "subjectOU": "IT Security",
  "subjectL": "San Francisco",
  "subjectST": "California",
  "subjectC": "US",
  "subjectE": "admin@example.com",
  "validityDays": 3650,
  "keySize": 4096,
  "keyUsage": ["keyCertSign", "cRLSign"],
  "basicConstraints": {
    "ca": true,
    "pathLength": 2
  }
}
```

**Validation Rules:**

- `subjectCN`: Required, max 64 chars
- `subjectC`: Optional, must be 2-letter ISO code
- `validityDays`: Required, min 365, max 7300 (20 years)
- `keySize`: Required, must be 2048 or 4096
- `keyUsage`: Required for CA, must include "keyCertSign"
- `basicConstraints.ca`: Must be true for Root CA

**Response:** `201 Created`

```json
{
  "id": 1,
  "serialNumber": "1a2b3c4d5e6f7890",
  "subjectDN": "CN=Root CA,O=Example Organization,C=US",
  "issuerDN": "CN=Root CA,O=Example Organization,C=US",
  "certificateType": "ROOT",
  "status": "VALID",
  "validFrom": "2025-10-15T10:00:00",
  "validTo": "2035-10-15T10:00:00",
  "keyUsage": "keyCertSign,cRLSign",
  "owner": {
    "id": 1,
    "email": "admin@example.com",
    "role": "ADMIN"
  },
  "createdAt": "2025-10-15T10:00:00"
}
```

**Error Responses:**

- `400 Bad Request`: Invalid input data
- `401 Unauthorized`: Not authenticated
- `403 Forbidden`: Not an ADMIN user

---

#### POST /api/certificates/intermediate

**Description:** Create an Intermediate CA certificate signed by a Root or another Intermediate CA

**Authorization:** `@PreAuthorize("hasRole('ADMIN')")`

**Request Body:**

```json
{
  "issuerCertificateId": 1,
  "subjectCN": "Intermediate CA - Engineering",
  "subjectO": "Example Organization",
  "subjectOU": "Engineering Department",
  "subjectL": "San Francisco",
  "subjectST": "California",
  "subjectC": "US",
  "subjectE": "ca-eng@example.com",
  "validityDays": 1825,
  "keySize": 2048,
  "keyUsage": ["keyCertSign", "cRLSign"],
  "basicConstraints": {
    "ca": true,
    "pathLength": 1
  }
}
```

**Validation Rules:**

- `issuerCertificateId`: Required, must exist and be a CA certificate (ROOT or INTERMEDIATE)
- Issuer certificate must be VALID (not revoked)
- Issuer must have `keyCertSign` in keyUsage
- `validityDays`: Must not exceed issuer's remaining validity
- `basicConstraints.pathLength`: Must be less than issuer's pathLength

**Response:** `201 Created`

```json
{
  "id": 2,
  "serialNumber": "2b3c4d5e6f7890ab",
  "subjectDN": "CN=Intermediate CA - Engineering,O=Example Organization,C=US",
  "issuerDN": "CN=Root CA,O=Example Organization,C=US",
  "certificateType": "INTERMEDIATE",
  "status": "VALID",
  "validFrom": "2025-10-15T10:00:00",
  "validTo": "2030-10-15T10:00:00",
  "keyUsage": "keyCertSign,cRLSign",
  "issuerCertificate": {
    "id": 1,
    "serialNumber": "1a2b3c4d5e6f7890",
    "subjectCN": "Root CA"
  },
  "owner": {
    "id": 1,
    "email": "admin@example.com",
    "role": "ADMIN"
  },
  "createdAt": "2025-10-15T10:00:00"
}
```

**Error Responses:**

- `400 Bad Request`: Invalid input or issuer certificate issues
- `404 Not Found`: Issuer certificate not found
- `403 Forbidden`: Not an ADMIN user

---

#### POST /api/certificates/end-entity

**Description:** Create an End-Entity certificate for users, servers, or devices

**Authorization:** `@PreAuthorize("hasAnyRole('ADMIN', 'CA_USER')")`

**Access Control:**

- ADMIN: Can issue for any organization
- CA_USER: Can only issue using their own CA certificate or certificates from their chain

**Request Body:**

```json
{
  "issuerCertificateId": 2,
  "templateId": 1,
  "subjectCN": "server.example.com",
  "subjectO": "Example Organization",
  "subjectOU": "Engineering",
  "subjectL": "San Francisco",
  "subjectST": "California",
  "subjectC": "US",
  "subjectE": "admin@server.example.com",
  "validityDays": 365,
  "keySize": 2048,
  "keyUsage": ["digitalSignature", "keyEncipherment"],
  "extendedKeyUsage": ["serverAuth", "clientAuth"],
  "subjectAlternativeNames": ["server.example.com", "www.server.example.com", "*.api.example.com"]
}
```

**Validation Rules:**

- `issuerCertificateId`: Required, must be CA certificate owned by requester (for CA_USER)
- `templateId`: Optional, if provided, validates against template constraints
- Template validation (if templateId provided):
  - `subjectCN` must match `commonNamePattern` regex
  - `subjectAlternativeNames` must match `sanPattern` regex
  - `validityDays` must not exceed template's `ttlDays`
- `keyUsage`: Must NOT include "keyCertSign" (not a CA)
- `basicConstraints.ca`: Must be false or omitted

**Response:** `201 Created`

```json
{
  "id": 3,
  "serialNumber": "3c4d5e6f7890abcd",
  "subjectDN": "CN=server.example.com,O=Example Organization,C=US",
  "issuerDN": "CN=Intermediate CA - Engineering,O=Example Organization,C=US",
  "certificateType": "END_ENTITY",
  "status": "VALID",
  "validFrom": "2025-10-15T10:00:00",
  "validTo": "2026-10-15T10:00:00",
  "keyUsage": "digitalSignature,keyEncipherment",
  "extendedKeyUsage": "serverAuth,clientAuth",
  "subjectAlternativeNames": "server.example.com,www.server.example.com,*.api.example.com",
  "issuerCertificate": {
    "id": 2,
    "serialNumber": "2b3c4d5e6f7890ab",
    "subjectCN": "Intermediate CA - Engineering"
  },
  "template": {
    "id": 1,
    "name": "Web Server Template"
  },
  "owner": {
    "id": 2,
    "email": "ca-user@example.com",
    "role": "CA_USER"
  },
  "createdAt": "2025-10-15T10:00:00"
}
```

**Error Responses:**

- `400 Bad Request`: Validation failed or template constraint violation
- `403 Forbidden`: CA_USER trying to use certificate outside their chain
- `404 Not Found`: Issuer certificate or template not found

---

#### GET /api/certificates

**Description:** List certificates with role-based filtering

**Authorization:** `@PreAuthorize("isAuthenticated()")`

**Access Control:**

- ADMIN: Returns all certificates
- CA_USER: Returns certificates from their chain (issued by their CA or descendants)
- REGULAR_USER: Returns only their own certificates

**Query Parameters:**

- `type`: Optional, filter by CertificateType (ROOT, INTERMEDIATE, END_ENTITY)
- `status`: Optional, filter by CertificateStatus (VALID, REVOKED)
- `page`: Optional, page number (default: 0)
- `size`: Optional, page size (default: 20, max: 100)

**Example Request:**

```
GET /api/certificates?type=END_ENTITY&status=VALID&page=0&size=20
```

**Response:** `200 OK`

```json
{
  "content": [
    {
      "id": 3,
      "serialNumber": "3c4d5e6f7890abcd",
      "subjectCN": "server.example.com",
      "subjectDN": "CN=server.example.com,O=Example Organization,C=US",
      "certificateType": "END_ENTITY",
      "status": "VALID",
      "validFrom": "2025-10-15T10:00:00",
      "validTo": "2026-10-15T10:00:00",
      "issuerCertificate": {
        "id": 2,
        "subjectCN": "Intermediate CA - Engineering"
      },
      "owner": {
        "email": "ca-user@example.com"
      }
    }
  ],
  "page": 0,
  "size": 20,
  "totalElements": 1,
  "totalPages": 1
}
```

---

#### GET /api/certificates/{serialNumber}

**Description:** Get detailed information about a specific certificate

**Authorization:** `@PreAuthorize("isAuthenticated()")`

**Access Control:**

- ADMIN: Can view any certificate
- CA_USER: Can view certificates from their chain
- REGULAR_USER: Can view only their own certificates

**Path Parameters:**

- `serialNumber`: Certificate serial number (hex string)

**Response:** `200 OK`

```json
{
  "id": 3,
  "serialNumber": "3c4d5e6f7890abcd",
  "subjectCN": "server.example.com",
  "subjectO": "Example Organization",
  "subjectOU": "Engineering",
  "subjectC": "US",
  "subjectE": "admin@server.example.com",
  "subjectDN": "CN=server.example.com,O=Example Organization,C=US",
  "issuerCN": "Intermediate CA - Engineering",
  "issuerDN": "CN=Intermediate CA - Engineering,O=Example Organization,C=US",
  "certificateType": "END_ENTITY",
  "status": "VALID",
  "validFrom": "2025-10-15T10:00:00",
  "validTo": "2026-10-15T10:00:00",
  "keyUsage": "digitalSignature,keyEncipherment",
  "extendedKeyUsage": "serverAuth,clientAuth",
  "subjectAlternativeNames": "server.example.com,www.server.example.com",
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki...\n-----END PUBLIC KEY-----",
  "certificateData": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIB...\n-----END CERTIFICATE-----",
  "issuerCertificate": {
    "id": 2,
    "serialNumber": "2b3c4d5e6f7890ab",
    "subjectCN": "Intermediate CA - Engineering"
  },
  "owner": {
    "id": 2,
    "email": "ca-user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "createdAt": "2025-10-15T10:00:00"
}
```

**Error Responses:**

- `403 Forbidden`: User doesn't have access to this certificate
- `404 Not Found`: Certificate not found

---

#### GET /api/certificates/{serialNumber}/download

**Description:** Download certificate with private key as PKCS12 keystore

**Authorization:** `@PreAuthorize("isAuthenticated()")`

**Access Control:**

- Certificate owner can download
- ADMIN can download any certificate

**Path Parameters:**

- `serialNumber`: Certificate serial number

**Query Parameters:**

- `format`: Keystore format (default: "pkcs12", options: "pkcs12", "pem")
- `password`: Keystore password (required for pkcs12)

**Example Request:**

```
GET /api/certificates/3c4d5e6f7890abcd/download?format=pkcs12&password=securePass123
```

**Response:** `200 OK`

- **Content-Type:** `application/x-pkcs12` (for PKCS12) or `application/x-pem-file` (for PEM)
- **Content-Disposition:** `attachment; filename="certificate-3c4d5e6f7890abcd.p12"`
- **Body:** Binary keystore file

**Process:**

1. Verify user has access to certificate
2. Decrypt private key using master key
3. Build certificate chain (from end-entity to root)
4. Create PKCS12 keystore with:

   - Private key
   - End-entity certificate
   - Intermediate certificates
   - Root certificate

5. Protect keystore with provided password
6. Return binary file

**Error Responses:**

- `400 Bad Request`: Missing or invalid password
- `403 Forbidden`: User doesn't own this certificate
- `404 Not Found`: Certificate not found

---

#### GET /api/certificates/{serialNumber}/chain

**Description:** Get complete certificate chain from end-entity to root

**Authorization:** `@PreAuthorize("isAuthenticated()")`

**Path Parameters:**

- `serialNumber`: Certificate serial number

**Response:** `200 OK`

```json
{
  "chain": [
    {
      "id": 3,
      "serialNumber": "3c4d5e6f7890abcd",
      "subjectCN": "server.example.com",
      "certificateType": "END_ENTITY",
      "certificateData": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    },
    {
      "id": 2,
      "serialNumber": "2b3c4d5e6f7890ab",
      "subjectCN": "Intermediate CA - Engineering",
      "certificateType": "INTERMEDIATE",
      "certificateData": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    },
    {
      "id": 1,
      "serialNumber": "1a2b3c4d5e6f7890",
      "subjectCN": "Root CA",
      "certificateType": "ROOT",
      "certificateData": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    }
  ],
  "chainLength": 3,
  "isValid": true
}
```

---

#### POST /api/certificates/{serialNumber}/revoke

**Description:** Revoke a certificate

**Authorization:** `@PreAuthorize("isAuthenticated()")`

**Access Control:**

- Certificate owner can revoke their own certificate
- CA_USER can revoke certificates they issued
- ADMIN can revoke any certificate

**Path Parameters:**

- `serialNumber`: Certificate serial number

**Request Body:**

```json
{
  "reason": "keyCompromise"
}
```

**Revocation Reasons (X.509 Standard):**

- `keyCompromise`: Private key has been compromised
- `cACompromise`: CA key has been compromised
- `affiliationChanged`: Subject's affiliation changed
- `superseded`: Certificate has been superseded
- `cessationOfOperation`: Certificate no longer needed
- `certificateHold`: Temporary revocation (can be reversed)
- `removeFromCRL`: Remove from CRL (only if previously on hold)
- `privilegeWithdrawn`: Privileges have been withdrawn
- `aACompromise`: Attribute authority compromised

**Response:** `200 OK`

```json
{
  "id": 3,
  "serialNumber": "3c4d5e6f7890abcd",
  "status": "REVOKED",
  "revocationReason": "keyCompromise",
  "revocationDate": "2025-10-15T15:30:00",
  "subjectCN": "server.example.com"
}
```

**Side Effects:**

- Certificate status updated to REVOKED
- CRL regenerated for the issuing CA
- Revoked certificates cannot be used for further issuance

**Error Responses:**

- `400 Bad Request`: Certificate already revoked or invalid reason
- `403 Forbidden`: User doesn't have permission to revoke
- `404 Not Found`: Certificate not found

### 5.2 CSRController

Endpoints:

- `POST /api/csr/create` - autogenerate CSR (REGULAR_USER)
- `POST /api/csr/upload` - upload external CSR (REGULAR_USER)
- `GET /api/csr/my-requests` - list user's CSRs (REGULAR_USER)
- `GET /api/csr/pending` - list pending CSRs for CA (CA_USER)
- `POST /api/csr/{id}/approve` - approve and issue certificate (CA_USER/ADMIN)
- `POST /api/csr/{id}/reject` - reject CSR (CA_USER/ADMIN)

### 5.3 TemplateController

Endpoints:

- `POST /api/templates` - create template (CA_USER)
- `GET /api/templates` - list CA user's templates (CA_USER)
- `PUT /api/templates/{id}` - update template (CA_USER - owner)
- `DELETE /api/templates/{id}` - delete template (CA_USER/ADMIN)

### 5.4 CRLController

Endpoints:

- `GET /api/crl/{caSerialNumber}` - get CRL in DER format (PUBLIC)

### 5.5 AdminController

Endpoints:

- `POST /api/admin/users/ca` - create CA user (ADMIN)
- `GET /api/admin/users` - list all users (ADMIN)
- `PUT /api/admin/users/{id}/role` - change user role (ADMIN)

## Phase 6: Security Configuration

### 6.1 Update SecurityConfig

- Add method security with `@EnableMethodSecurity`
- Configure role-based endpoint protection
- Add CORS configuration for frontend
- Keep JWT authentication filter

### 6.2 Update JwtUtil

- Add role claims to JWT tokens
- Extract role from token for authorization

### 6.3 HTTPS Configuration

- Generate self-signed certificate for development
- Configure `application.properties`:
- `server.port=8443`
- `server.ssl.enabled=true`
- `server.ssl.key-store=classpath:keystore.p12`
- `server.ssl.key-store-password=changeit`
- `server.ssl.key-store-type=PKCS12`
- Create keystore using keytool or PKI system itself
- Add HTTP to HTTPS redirect configuration

### 6.4 Exception Handling

Create global exception handler:

- `@RestControllerAdvice` for consistent error responses
- Handle validation errors, authorization errors, certificate errors
- Return proper HTTP status codes

## Phase 7: Configuration & Dependencies

### 7.1 Update pom.xml

Add dependencies:

- Bouncy Castle: `bcpkix-jdk18on` (v1.78+)
- Bouncy Castle provider: `bcprov-jdk18on` (v1.78+)

### 7.2 Update application.properties

- Switch to H2 database: `spring.datasource.url=jdbc:h2:mem:pki_db`
- H2 console: `spring.h2.console.enabled=true`
- Add encryption master key: `app.encryption.master-key=<base64-encoded-key>`
- HTTPS configuration
- JWT secret and expiration
- Keep existing email and MFA settings

### 7.3 Database Initialization

- Create `data.sql` for initial admin user
- Add sample organizations

## Phase 8: Testing & Validation

### 8.1 Manual Testing Checklist

- Test certificate generation (Root → Intermediate → End-Entity)
- Test certificate chain validation
- Test private key encryption/decryption
- Test CSR workflow (create → approve → issue)
- Test template validation
- Test certificate revocation and CRL generation
- Test role-based access control
- Test HTTPS endpoints

### 8.2 Integration Points

- Verify JWT authentication works with new roles
- Verify MFA still works with role-based access
- Test certificate download in PKCS12 format
- Verify CRL is accessible publicly

## Implementation Notes

### Key Standards & Best Practices

- Follow X.509 v3 certificate standard
- Use X.500 Distinguished Names (DN) properly
- Implement proper certificate chain validation
- Use secure random for serial numbers (128-bit)
- Follow NIST guidelines for key sizes (min 2048-bit RSA)
- Implement proper error handling and logging
- Use BCrypt for password hashing (already in place)
- Store all dates in UTC

### Security Considerations

- Never expose private keys in API responses
- Decrypt private keys only when needed (download)
- Validate all inputs (DN fields, extensions, patterns)
- Implement rate limiting for certificate issuance
- Log all certificate operations (issuance, revocation)
- Validate certificate chains before issuance
- Check CRL before issuing new certificates

### REST API Standards

- Use proper HTTP methods (GET, POST, PUT, DELETE)
- Return appropriate status codes (200, 201, 400, 401, 403, 404)
- Use consistent error response format
- Implement pagination for list endpoints
- Use query parameters for filtering
- Follow RESTful naming conventions