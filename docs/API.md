# API Documentation

This document provides comprehensive API reference for all services in the PKI system, including method signatures, parameters, return types, exceptions, and implementation status.

## Crypto Layer API

The crypto layer provides internal APIs for cryptographic operations using Bouncy Castle library.

### KeyPairGeneratorService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.KeyPairGeneratorService`

#### generateKeyPair

**Signature**: `KeyPair generateKeyPair(int keySize)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| keySize | int | Yes | Key size in bits (2048 or 4096) |

**Return Type**: `KeyPair`

**Exceptions**:
- `IllegalArgumentException`: If key size is not 2048 or 4096 bits
- `RuntimeException`: If RSA algorithm is not available

**Implementation Status**: ✅ Implemented

**Example**:
```java
KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
```

---

### CertificateGeneratorService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.CertificateGeneratorService`

#### buildX500Name

**Signature**: `X500Name buildX500Name(String cn, String o, String ou, String l, String st, String c, String e)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| cn | String | Yes | Common Name (cannot be empty) |
| o | String | No | Organization |
| ou | String | No | Organizational Unit |
| l | String | No | Locality |
| st | String | No | State |
| c | String | No | Country (2-letter ISO code) |
| e | String | No | Email (valid format required) |

**Return Type**: `X500Name`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters (empty CN, invalid country codes, invalid email formats)

**Implementation Status**: ✅ Implemented

#### generateSerialNumber

**Signature**: `BigInteger generateSerialNumber()`

**Parameters**: None

**Return Type**: `BigInteger`

**Exceptions**: None

**Implementation Status**: ✅ Implemented

#### generateRootCertificate

**Signature**: `X509Certificate generateRootCertificate(KeyPair keyPair, X500Name subjectDN, int validityDays, List<String> keyUsage, Integer pathLength)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| keyPair | KeyPair | Yes | RSA key pair for the certificate |
| subjectDN | X500Name | Yes | Subject Distinguished Name |
| validityDays | int | Yes | Certificate validity period in days |
| keyUsage | List<String> | Yes | List of key usage strings |
| pathLength | Integer | No | Path length constraint (null for unlimited) |

**Return Type**: `X509Certificate`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `RuntimeException`: For certificate generation failures

**Implementation Status**: ✅ Implemented

#### generateIntermediateCertificate

**Signature**: `X509Certificate generateIntermediateCertificate(KeyPair keyPair, X500Name subjectDN, int validityDays, List<String> keyUsage, Integer pathLength, X509Certificate issuerCert, PrivateKey issuerKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| keyPair | KeyPair | Yes | RSA key pair for the certificate |
| subjectDN | X500Name | Yes | Subject Distinguished Name |
| validityDays | int | Yes | Certificate validity period in days |
| keyUsage | List<String> | Yes | List of key usage strings |
| pathLength | Integer | No | Path length constraint |
| issuerCert | X509Certificate | Yes | Issuer certificate |
| issuerKey | PrivateKey | Yes | Issuer private key |

**Return Type**: `X509Certificate`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `RuntimeException`: For certificate generation failures

**Implementation Status**: ✅ Implemented

#### generateEndEntityCertificate

**Signature**: `X509Certificate generateEndEntityCertificate(KeyPair keyPair, X500Name subjectDN, int validityDays, List<String> keyUsage, List<String> extendedKeyUsage, List<String> subjectAlternativeNames, X509Certificate issuerCert, PrivateKey issuerKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| keyPair | KeyPair | Yes | RSA key pair for the certificate |
| subjectDN | X500Name | Yes | Subject Distinguished Name |
| validityDays | int | Yes | Certificate validity period in days |
| keyUsage | List<String> | Yes | List of key usage strings |
| extendedKeyUsage | List<String> | No | List of extended key usage strings |
| subjectAlternativeNames | List<String> | No | List of subject alternative names |
| issuerCert | X509Certificate | Yes | Issuer certificate |
| issuerKey | PrivateKey | Yes | Issuer private key |

**Return Type**: `X509Certificate`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `RuntimeException`: For certificate generation failures

**Implementation Status**: ✅ Implemented

---

### CertificateSignerService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.CertificateSignerService`

#### signCertificate

**Signature**: `X509Certificate signCertificate(X509Certificate certificate, PrivateKey signingKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| certificate | X509Certificate | Yes | Certificate to sign |
| signingKey | PrivateKey | Yes | Private key for signing |

**Return Type**: `X509Certificate`

**Exceptions**:
- `IllegalArgumentException`: For null parameters
- `RuntimeException`: For signing failures

**Implementation Status**: ✅ Implemented

#### verifyCertificateSignature

**Signature**: `boolean verifyCertificateSignature(X509Certificate certificate, PublicKey publicKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| certificate | X509Certificate | Yes | Certificate to verify |
| publicKey | PublicKey | Yes | Public key for verification |

**Return Type**: `boolean`

**Exceptions**:
- `IllegalArgumentException`: For null parameters
- `RuntimeException`: For verification failures

**Implementation Status**: ✅ Implemented

---

### EncryptionService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.EncryptionService`

#### encryptPrivateKey

**Signature**: `EncryptedData encryptPrivateKey(PrivateKey privateKey, String masterKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | PrivateKey | Yes | Private key to encrypt |
| masterKey | String | Yes | Base64-encoded 256-bit master key |

**Return Type**: `EncryptedData`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters (null keys, invalid master key format)
- `RuntimeException`: For encryption failures

**Implementation Status**: ✅ Implemented

#### decryptPrivateKey

**Signature**: `PrivateKey decryptPrivateKey(EncryptedData encryptedData, String masterKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| encryptedData | EncryptedData | Yes | Encrypted data containing private key |
| masterKey | String | Yes | Base64-encoded 256-bit master key |

**Return Type**: `PrivateKey`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `SecurityException`: For decryption failures (tampered data, invalid tag)

**Implementation Status**: ✅ Implemented

---

### KeystoreService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.KeystoreService`

#### createPKCS12Keystore (Single Certificate)

**Signature**: `byte[] createPKCS12Keystore(PrivateKey privateKey, X509Certificate certificate, String password)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | PrivateKey | Yes | Private key to include |
| certificate | X509Certificate | Yes | Certificate to include |
| password | String | Yes | Keystore password (minimum 6 characters) |

**Return Type**: `byte[]`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters (null keys, short passwords)
- `RuntimeException`: For keystore creation failures

**Implementation Status**: ✅ Implemented

#### createPKCS12Keystore (Certificate Chain)

**Signature**: `byte[] createPKCS12Keystore(PrivateKey privateKey, List<X509Certificate> certificateChain, String password, String privateKeyAlias, String certificateAlias)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | PrivateKey | Yes | Private key to include |
| certificateChain | List<X509Certificate> | Yes | Certificate chain (cannot be null or empty) |
| password | String | Yes | Keystore password (minimum 6 characters) |
| privateKeyAlias | String | Yes | Alias for private key |
| certificateAlias | String | Yes | Alias for certificate |

**Return Type**: `byte[]`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `RuntimeException`: For keystore creation failures

**Implementation Status**: ✅ Implemented

#### exportCertificateAsPEM

**Signature**: `String exportCertificateAsPEM(X509Certificate certificate)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| certificate | X509Certificate | Yes | Certificate to export |

**Return Type**: `String`

**Exceptions**:
- `IllegalArgumentException`: For null certificate
- `RuntimeException`: For export failures

**Implementation Status**: ✅ Implemented

#### exportPrivateKeyAsPEM

**Signature**: `String exportPrivateKeyAsPEM(PrivateKey privateKey)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| privateKey | PrivateKey | Yes | Private key to export |

**Return Type**: `String` (PKCS#8 format)

**Exceptions**:
- `IllegalArgumentException`: For null private key
- `RuntimeException`: For export failures

**Implementation Status**: ✅ Implemented

---

### CRLGeneratorService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.crypto.CRLGeneratorService`

#### generateCRL

**Signature**: `X509CRL generateCRL(X509Certificate caCertificate, PrivateKey caPrivateKey, List<BigInteger> revokedSerialNumbers, String crlDistributionPoint)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| caCertificate | X509Certificate | Yes | CA certificate (must be CA type) |
| caPrivateKey | PrivateKey | Yes | CA private key |
| revokedSerialNumbers | List<BigInteger> | Yes | List of revoked certificate serial numbers |
| crlDistributionPoint | String | Yes | Valid HTTP/HTTPS URL for CRL distribution |

**Return Type**: `X509CRL`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters (null certificates, invalid URLs, non-CA certificates)
- `RuntimeException`: For CRL generation failures

**Implementation Status**: ✅ Implemented

## Business Logic API

The business logic layer provides high-level operations and orchestrates crypto layer services.

### ValidationService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.ValidationService`

#### validateIssuerCertificate

**Signature**: `void validateIssuerCertificate(Certificate certificate)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| certificate | Certificate | Yes | Certificate to validate |

**Return Type**: `void`

**Exceptions**:
- `InvalidCertificateException`: For certificate validation failures (expired, not yet valid, revoked, wrong type, missing key usage)

**Implementation Status**: ✅ Implemented

#### validateCertificateChain

**Signature**: `void validateCertificateChain(List<Certificate> chain)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| chain | List<Certificate> | Yes | Certificate chain to validate |

**Return Type**: `void`

**Exceptions**:
- `InvalidCertificateChainException`: For chain validation failures (doesn't terminate at root, broken chain)

**Implementation Status**: ✅ Implemented

#### validateTemplateConstraints

**Signature**: `void validateTemplateConstraints(CreateEndEntityCertificateDTO request, CertificateTemplate template)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request | CreateEndEntityCertificateDTO | Yes | Certificate request to validate |
| template | CertificateTemplate | Yes | Template with constraints |

**Return Type**: `void`

**Exceptions**:
- `TemplateConstraintViolationException`: For template constraint violations (CN pattern, validity period, key usage)

**Implementation Status**: ✅ Implemented

#### validateCertificateRequest

**Signature**: `void validateCertificateRequest(CreateEndEntityCertificateDTO request)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request | CreateEndEntityCertificateDTO | Yes | Certificate request to validate |

**Return Type**: `void`

**Exceptions**:
- `ValidationException`: For validation failures (invalid email, country code, empty CN)

**Implementation Status**: ✅ Implemented

#### validateRevocationRequest

**Signature**: `void validateRevocationRequest(String serialNumber, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| serialNumber | String | Yes | Serial number of certificate to revoke |
| requester | User | Yes | User requesting revocation |

**Return Type**: `void`

**Exceptions**:
- `UnauthorizedException`: For permission violations
- `IllegalStateException`: For invalid state operations (already revoked)

**Implementation Status**: ✅ Implemented

---

### CertificateService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.CertificateService`

#### createRootCertificate

**Signature**: `CertificateDTO createRootCertificate(CreateRootCertificateDTO dto, User admin)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| dto | CreateRootCertificateDTO | Yes | Root certificate creation data |
| admin | User | Yes | Admin user (must have ADMIN role) |

**Return Type**: `CertificateDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `UnauthorizedException`: For permission violations

**Implementation Status**: ✅ Implemented

#### createIntermediateCertificate

**Signature**: `CertificateDTO createIntermediateCertificate(CreateIntermediateCertificateDTO dto, User admin)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| dto | CreateIntermediateCertificateDTO | Yes | Intermediate certificate creation data |
| admin | User | Yes | Admin user (must have ADMIN role) |

**Return Type**: `CertificateDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `UnauthorizedException`: For permission violations

**Implementation Status**: ⏳ Pending

#### createEndEntityCertificate

**Signature**: `CertificateDTO createEndEntityCertificate(CreateEndEntityCertificateDTO dto, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| dto | CreateEndEntityCertificateDTO | Yes | End-entity certificate creation data |
| requester | User | Yes | User requesting certificate |

**Return Type**: `CertificateDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `UnauthorizedException`: For permission violations

**Implementation Status**: ⏳ Pending

#### getCertificateBySerialNumber

**Signature**: `CertificateDTO getCertificateBySerialNumber(String serialNumber, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| serialNumber | String | Yes | Certificate serial number |
| requester | User | Yes | User requesting certificate |

**Return Type**: `CertificateDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `NotFoundException`: For missing certificates
- `UnauthorizedException`: For permission violations

**Implementation Status**: ⏳ Pending

#### listCertificates

**Signature**: `Page<CertificateDTO> listCertificates(CertificateType type, CertificateStatus status, Pageable pageable, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| type | CertificateType | No | Filter by certificate type |
| status | CertificateStatus | No | Filter by certificate status |
| pageable | Pageable | Yes | Pagination parameters |
| requester | User | Yes | User requesting certificates |

**Return Type**: `Page<CertificateDTO>`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `UnauthorizedException`: For permission violations

**Implementation Status**: ⏳ Pending

#### getCertificateChain

**Signature**: `CertificateChainDTO getCertificateChain(String serialNumber)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| serialNumber | String | Yes | Certificate serial number |

**Return Type**: `CertificateChainDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `NotFoundException`: For missing certificates

**Implementation Status**: ⏳ Pending

#### revokeCertificate

**Signature**: `CertificateDTO revokeCertificate(String serialNumber, RevokeCertificateDTO dto, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| serialNumber | String | Yes | Certificate serial number |
| dto | RevokeCertificateDTO | Yes | Revocation data |
| requester | User | Yes | User requesting revocation |

**Return Type**: `CertificateDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `NotFoundException`: For missing certificates
- `UnauthorizedException`: For permission violations

**Implementation Status**: ⏳ Pending

#### downloadCertificate

**Signature**: `byte[] downloadCertificate(String serialNumber, String format, String password, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| serialNumber | String | Yes | Certificate serial number |
| format | String | Yes | Download format (PEM, PKCS12) |
| password | String | No | Password for PKCS12 format |
| requester | User | Yes | User requesting download |

**Return Type**: `byte[]`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters
- `NotFoundException`: For missing certificates
- `UnauthorizedException`: For permission violations

**Implementation Status**: ⏳ Pending

---

### TemplateService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.TemplateService`

#### createTemplate

**Signature**: `TemplateDTO createTemplate(CreateTemplateDTO dto, User caUser)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| dto | CreateTemplateDTO | Yes | Template creation data |
| caUser | User | Yes | CA user (must have CA_USER role) |

**Return Type**: `TemplateDTO`

**Exceptions**:
- `UnsupportedOperationException`: Method not implemented

**Implementation Status**: ⏳ Skeleton

#### updateTemplate

**Signature**: `TemplateDTO updateTemplate(Long templateId, UpdateTemplateDTO dto, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| templateId | Long | Yes | Template ID |
| dto | UpdateTemplateDTO | Yes | Template update data |
| requester | User | Yes | User requesting update |

**Return Type**: `TemplateDTO`

**Exceptions**:
- `UnsupportedOperationException`: Method not implemented

**Implementation Status**: ⏳ Skeleton

#### deleteTemplate

**Signature**: `void deleteTemplate(Long templateId, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| templateId | Long | Yes | Template ID |
| requester | User | Yes | User requesting deletion |

**Return Type**: `void`

**Exceptions**:
- `UnsupportedOperationException`: Method not implemented

**Implementation Status**: ⏳ Skeleton

#### listTemplates

**Signature**: `Page<TemplateDTO> listTemplates(Pageable pageable, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| pageable | Pageable | Yes | Pagination parameters |
| requester | User | Yes | User requesting templates |

**Return Type**: `Page<TemplateDTO>`

**Exceptions**:
- `UnsupportedOperationException`: Method not implemented

**Implementation Status**: ⏳ Skeleton

#### getTemplateById

**Signature**: `TemplateDTO getTemplateById(Long templateId, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| templateId | Long | Yes | Template ID |
| requester | User | Yes | User requesting template |

**Return Type**: `TemplateDTO`

**Exceptions**:
- `UnsupportedOperationException`: Method not implemented

**Implementation Status**: ⏳ Skeleton

#### listTemplatesForCA

**Signature**: `Page<TemplateDTO> listTemplatesForCA(Long caCertificateId, Pageable pageable)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| caCertificateId | Long | Yes | CA certificate ID |
| pageable | Pageable | Yes | Pagination parameters |

**Return Type**: `Page<TemplateDTO>`

**Exceptions**:
- `UnsupportedOperationException`: Method not implemented

**Implementation Status**: ⏳ Skeleton

---

### CSRService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.CSRService`

#### createCSR

**Signature**: `CSRDTO createCSR(CreateCSRDTO dto, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| dto | CreateCSRDTO | Yes | CSR creation data |
| requester | User | Yes | User creating CSR |

**Return Type**: `CSRDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### uploadCSR

**Signature**: `CSRDTO uploadCSR(UploadCSRDTO dto, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| dto | UploadCSRDTO | Yes | CSR upload data |
| requester | User | Yes | User uploading CSR |

**Return Type**: `CSRDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### listUserCSRs

**Signature**: `Page<CSRDTO> listUserCSRs(User requester, Pageable pageable)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| requester | User | Yes | User requesting CSRs |
| pageable | Pageable | Yes | Pagination parameters |

**Return Type**: `Page<CSRDTO>`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### listPendingCSRs

**Signature**: `Page<CSRDTO> listPendingCSRs(User approver, Pageable pageable)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| approver | User | Yes | User approving CSRs |
| pageable | Pageable | Yes | Pagination parameters |

**Return Type**: `Page<CSRDTO>`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### approveCSR

**Signature**: `CSRDTO approveCSR(Long csrId, ApproveCSRDTO dto, User approver)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| csrId | Long | Yes | CSR ID |
| dto | ApproveCSRDTO | Yes | Approval data |
| approver | User | Yes | User approving CSR |

**Return Type**: `CSRDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### rejectCSR

**Signature**: `CSRDTO rejectCSR(Long csrId, RejectCSRDTO dto, User approver)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| csrId | Long | Yes | CSR ID |
| dto | RejectCSRDTO | Yes | Rejection data |
| approver | User | Yes | User rejecting CSR |

**Return Type**: `CSRDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### getCSRById

**Signature**: `CSRDTO getCSRById(Long csrId, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| csrId | Long | Yes | CSR ID |
| requester | User | Yes | User requesting CSR |

**Return Type**: `CSRDTO`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

---

### CRLService API

**Service**: `com.ftn.siit.ib.public_key_infrastructure.services.CRLService`

#### generateCRL

**Signature**: `byte[] generateCRL(Long caCertificateId, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| caCertificateId | Long | Yes | CA certificate ID |
| requester | User | Yes | User requesting CRL generation |

**Return Type**: `byte[]`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### getCRL

**Signature**: `byte[] getCRL(Long caCertificateId)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| caCertificateId | Long | Yes | CA certificate ID |

**Return Type**: `byte[]`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### updateCRL

**Signature**: `byte[] updateCRL(Long caCertificateId, User requester)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| caCertificateId | Long | Yes | CA certificate ID |
| requester | User | Yes | User requesting CRL update |

**Return Type**: `byte[]`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

#### checkRevocationStatus

**Signature**: `boolean checkRevocationStatus(String serialNumber, Long caCertificateId)`

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| serialNumber | String | Yes | Certificate serial number |
| caCertificateId | Long | Yes | CA certificate ID |

**Return Type**: `boolean`

**Exceptions**:
- `IllegalArgumentException`: For invalid parameters

**Implementation Status**: ⚠️ Placeholder

## Authorization Requirements

### User Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| ADMIN | System administrator | Full system access, can manage all certificates and users |
| CA_USER | Certificate Authority user | Can create intermediate and end-entity certificates, manage templates |
| REGULAR_USER | Regular user | Can request certificates, view own certificates |

### Method-Level Security

| Service | Method | Required Role | Additional Requirements |
|---------|--------|---------------|------------------------|
| CertificateService | createRootCertificate | ADMIN | None |
| CertificateService | createIntermediateCertificate | ADMIN | None |
| CertificateService | createEndEntityCertificate | CA_USER, REGULAR_USER | CA_USER can create any, REGULAR_USER can create own |
| CertificateService | getCertificateBySerialNumber | ADMIN, REGULAR_USER | ADMIN can access any, REGULAR_USER can access own |
| CertificateService | listCertificates | ADMIN, REGULAR_USER | ADMIN can see all, REGULAR_USER can see own |
| CertificateService | revokeCertificate | ADMIN, REGULAR_USER | ADMIN can revoke any, REGULAR_USER can revoke own |
| TemplateService | createTemplate | CA_USER | Must own the CA certificate |
| TemplateService | updateTemplate | ADMIN, CA_USER | ADMIN can update any, CA_USER can update own |
| TemplateService | deleteTemplate | ADMIN, CA_USER | ADMIN can delete any, CA_USER can delete own |
| CSRService | createCSR | REGULAR_USER | Can create own CSRs |
| CSRService | approveCSR | CA_USER | Can approve CSRs for own CA |
| CSRService | rejectCSR | CA_USER | Can reject CSRs for own CA |

## Error Handling

### Exception Hierarchy

```
RuntimeException
├── IllegalArgumentException (Invalid parameters)
├── SecurityException (Security violations)
├── UnsupportedOperationException (Unimplemented methods)
├── ValidationException (General validation failures)
├── InvalidCertificateException (Certificate validation failures)
├── InvalidCertificateChainException (Chain validation failures)
├── TemplateConstraintViolationException (Template constraint violations)
├── UnauthorizedException (Permission violations)
├── NotFoundException (Resource not found)
├── ForbiddenException (Access forbidden)
└── IllegalStateException (Invalid state operations)
```

### Error Response Format

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Invalid certificate serial number",
  "path": "/api/certificates/12345"
}
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
| CSRService | ⚠️ Placeholder | 0% (placeholder implementations) |
| CRLService | ⚠️ Placeholder | 0% (placeholder implementations) |
