# Tests Documentation

This document provides comprehensive documentation of the test suite for the PKI system, including test structure, coverage, patterns, and statistics.

## Test Overview

The PKI system uses a comprehensive test suite with 303 tests covering all implemented services. The testing approach follows Test-Driven Development (TDD) principles for the crypto layer and mock-based testing for business logic services.

### Test Statistics
- **Total Tests**: 303
- **Failures**: 1 (minor test isolation issue)
- **Errors**: 1 (cleanup issue)
- **Success Rate**: 99.3%

## Test Organization

The test suite is organized using JUnit 5's `@Nested` and `@DisplayName` annotations for clear test structure and readable test names.

### Test Structure Pattern
```java
@ExtendWith(MockitoExtension.class)
class ServiceTest {
    
    @Nested
    @DisplayName("MethodName Tests")
    class MethodNameTests {
        
        @Test
        @DisplayName("should succeed when valid parameters provided")
        void shouldSucceedWhenValidParametersProvided() {
            // Test implementation
        }
        
        @Test
        @DisplayName("should throw exception when invalid parameters provided")
        void shouldThrowExceptionWhenInvalidParametersProvided() {
            // Test implementation
        }
    }
}
```

## Crypto Layer Tests

### KeyPairGeneratorServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/crypto/KeyPairGeneratorServiceTest.java`

**Test Coverage**:
- Key size validation (2048 and 4096 bits)
- Algorithm validation (RSA)
- Key pair generation success scenarios
- Invalid key size handling

**Key Test Methods**:
```java
@Nested
@DisplayName("Generate Key Pair Tests")
class GenerateKeyPairTests {
    
    @Test
    @DisplayName("should generate 2048-bit key pair successfully")
    void shouldGenerate2048BitKeyPairSuccessfully()
    
    @Test
    @DisplayName("should generate 4096-bit key pair successfully")
    void shouldGenerate4096BitKeyPairSuccessfully()
    
    @Test
    @DisplayName("should throw exception when key size is invalid")
    void shouldThrowExceptionWhenKeySizeIsInvalid()
}
```

**Test Patterns**:
- Direct service testing (no mocking needed)
- Parameter validation testing
- Key size verification using RSA key interfaces

---

### CertificateGeneratorServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/crypto/CertificateGeneratorServiceTest.java`

**Test Coverage**:
- X.500 Distinguished Name building
- Certificate generation (root, intermediate, end-entity)
- Extension handling (KeyUsage, ExtendedKeyUsage, BasicConstraints)
- Parameter validation
- Email format validation
- Country code validation

**Key Test Methods**:
```java
@Nested
@DisplayName("Build X500 Name Tests")
class BuildX500NameTests {
    
    @Test
    @DisplayName("should build X500 name with all components")
    void shouldBuildX500NameWithAllComponents()
    
    @Test
    @DisplayName("should throw exception when CN is empty")
    void shouldThrowExceptionWhenCNIsEmpty()
    
    @Test
    @DisplayName("should throw exception when country code is invalid")
    void shouldThrowExceptionWhenCountryCodeIsInvalid()
}

@Nested
@DisplayName("Generate Root Certificate Tests")
class GenerateRootCertificateTests {
    
    @Test
    @DisplayName("should generate root certificate successfully")
    void shouldGenerateRootCertificateSuccessfully()
    
    @Test
    @DisplayName("should throw exception when key pair is null")
    void shouldThrowExceptionWhenKeyPairIsNull()
}
```

**Test Patterns**:
- Direct service testing with Bouncy Castle integration
- Comprehensive parameter validation
- Certificate structure verification
- Extension validation

---

### CertificateSignerServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/crypto/CertificateSignerServiceTest.java`

**Test Coverage**:
- Certificate signing
- Signature verification
- Invalid signature detection
- Parameter validation

**Key Test Methods**:
```java
@Nested
@DisplayName("Sign Certificate Tests")
class SignCertificateTests {
    
    @Test
    @DisplayName("should sign certificate successfully")
    void shouldSignCertificateSuccessfully()
    
    @Test
    @DisplayName("should throw exception when certificate is null")
    void shouldThrowExceptionWhenCertificateIsNull()
}

@Nested
@DisplayName("Verify Certificate Signature Tests")
class VerifyCertificateSignatureTests {
    
    @Test
    @DisplayName("should verify valid signature successfully")
    void shouldVerifyValidSignatureSuccessfully()
    
    @Test
    @DisplayName("should return false for invalid signature")
    void shouldReturnFalseForInvalidSignature()
}
```

**Test Patterns**:
- Integration testing with Bouncy Castle
- Signature verification testing
- Error condition testing

---

### EncryptionServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/crypto/EncryptionServiceTest.java`

**Test Coverage**:
- AES-256-GCM encryption/decryption
- Master key validation
- Parameter validation
- Tampered data detection
- Tag validation

**Key Test Methods**:
```java
@Nested
@DisplayName("Encrypt Private Key Tests")
class EncryptPrivateKeyTests {
    
    @Test
    @DisplayName("should encrypt private key successfully")
    void shouldEncryptPrivateKeySuccessfully()
    
    @Test
    @DisplayName("should throw exception when private key is null")
    void shouldThrowExceptionWhenPrivateKeyIsNull()
    
    @Test
    @DisplayName("should throw exception when master key is null")
    void shouldThrowExceptionWhenMasterKeyIsNull()
}

@Nested
@DisplayName("Decrypt Private Key Tests")
class DecryptPrivateKeyTests {
    
    @Test
    @DisplayName("should decrypt private key successfully")
    void shouldDecryptPrivateKeySuccessfully()
    
    @Test
    @DisplayName("should throw SecurityException when data is tampered")
    void shouldThrowSecurityExceptionWhenDataIsTampered()
}
```

**Test Patterns**:
- Cryptographic operation testing
- Security validation testing
- Parameter validation with `@NullAndEmptySource`
- Tampered data detection testing

---

### KeystoreServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/crypto/KeystoreServiceTest.java`

**Test Coverage**:
- PKCS12 keystore creation
- PEM format export (certificates, private keys, public keys)
- Certificate chain handling
- Password validation
- Format validation

**Key Test Methods**:
```java
@Nested
@DisplayName("Create PKCS12 Keystore Tests")
class CreatePKCS12KeystoreTests {
    
    @Test
    @DisplayName("should create PKCS12 keystore with single certificate")
    void shouldCreatePKCS12KeystoreWithSingleCertificate()
    
    @Test
    @DisplayName("should create PKCS12 keystore with certificate chain")
    void shouldCreatePKCS12KeystoreWithCertificateChain()
    
    @Test
    @DisplayName("should throw exception when password is too short")
    void shouldThrowExceptionWhenPasswordIsTooShort()
}

@Nested
@DisplayName("Export Certificate As PEM Tests")
class ExportCertificateAsPEMTests {
    
    @Test
    @DisplayName("should export certificate as PEM successfully")
    void shouldExportCertificateAsPEMSuccessfully()
    
    @Test
    @DisplayName("should throw exception when certificate is null")
    void shouldThrowExceptionWhenCertificateIsNull()
}
```

**Test Patterns**:
- Keystore format validation
- PEM format validation
- Password strength testing
- Certificate chain testing

---

### CRLGeneratorServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/crypto/CRLGeneratorServiceTest.java`

**Test Coverage**:
- CRL generation
- Revoked certificate handling
- CRL distribution point validation
- Parameter validation

**Key Test Methods**:
```java
@Nested
@DisplayName("Generate CRL Tests")
class GenerateCRLTests {
    
    @Test
    @DisplayName("should generate CRL successfully")
    void shouldGenerateCRLSuccessfully()
    
    @Test
    @DisplayName("should throw exception when CA certificate is null")
    void shouldThrowExceptionWhenCACertificateIsNull()
    
    @Test
    @DisplayName("should throw exception when CRL distribution point is invalid")
    void shouldThrowExceptionWhenCrlDistributionPointIsInvalid()
}
```

**Test Patterns**:
- CRL structure validation
- URL validation testing
- Revocation list testing

## Business Logic Tests

### ValidationServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/ValidationServiceTest.java`

**Test Coverage**:
- Certificate validation (expired, not yet valid, revoked, type validation)
- Certificate chain validation (termination at root, broken chains)
- Template constraint validation (CN patterns, validity periods, key usage)
- Request validation (DN fields, email formats, country codes)
- Permission validation (revocation requests)

**Key Test Methods**:
```java
@Nested
@DisplayName("Validate Issuer Certificate Tests")
class ValidateIssuerCertificateTests {
    
    @Test
    @DisplayName("should validate successfully for valid root certificate")
    void shouldValidateSuccessfullyForValidRootCertificate()
    
    @Test
    @DisplayName("should throw exception when certificate is expired")
    void shouldThrowExceptionWhenCertificateIsExpired()
    
    @Test
    @DisplayName("should throw exception when certificate type is end entity")
    void shouldThrowExceptionWhenCertificateTypeIsEndEntity()
}

@Nested
@DisplayName("Validate Certificate Chain Tests")
class ValidateCertificateChainTests {
    
    @Test
    @DisplayName("should validate successfully for valid certificate chain")
    void shouldValidateSuccessfullyForValidCertificateChain()
    
    @Test
    @DisplayName("should throw exception when chain does not terminate at root")
    void shouldThrowExceptionWhenChainDoesNotTerminateAtRoot()
    
    @Test
    @DisplayName("should throw exception when chain is broken")
    void shouldThrowExceptionWhenChainIsBroken()
}
```

**Test Patterns**:
- Mock-based testing with `@Mock` and `@InjectMocks`
- Comprehensive validation testing
- Exception type validation
- Permission testing

---

### CertificateServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/CertificateServiceTest.java`

**Test Coverage**:
- Root certificate creation
- Parameter validation
- Permission validation
- DTO conversion
- Service integration

**Key Test Methods**:
```java
@Nested
@DisplayName("Create Root Certificate Tests")
class CreateRootCertificateTests {
    
    @Test
    @DisplayName("should create root certificate successfully")
    void shouldCreateRootCertificateSuccessfully()
    
    @Test
    @DisplayName("should throw exception when DTO is null")
    void shouldThrowExceptionWhenDTOIsNull()
    
    @Test
    @DisplayName("should throw exception when user is not admin")
    void shouldThrowExceptionWhenUserIsNotAdmin()
}
```

**Test Patterns**:
- Mock-based testing for dependencies
- DTO validation testing
- Permission testing
- Service integration testing

---

### TemplateServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/TemplateServiceTest.java`

**Test Coverage**:
- Template CRUD operations (skeleton methods)
- Parameter validation
- Permission validation
- Repository interaction

**Key Test Methods**:
```java
@Nested
@DisplayName("Create Template Tests")
class CreateTemplateTests {
    
    @Test
    @DisplayName("should throw UnsupportedOperationException")
    void shouldThrowUnsupportedOperationException()
    
    @Test
    @DisplayName("should throw exception when DTO is null")
    void shouldThrowExceptionWhenDTOIsNull()
}
```

**Test Patterns**:
- Skeleton method testing (expecting `UnsupportedOperationException`)
- Mock repository testing
- Parameter validation testing

---

### CSRServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/CSRServiceTest.java`

**Test Coverage**:
- CSR workflow operations (placeholder implementations)
- Parameter validation
- Status management
- User permission testing

**Key Test Methods**:
```java
@Nested
@DisplayName("Create CSR Tests")
class CreateCSRTests {
    
    @Test
    @DisplayName("should create CSR successfully")
    void shouldCreateCSRSuccessfully()
    
    @Test
    @DisplayName("should throw exception when DTO is null")
    void shouldThrowExceptionWhenDTOIsNull()
}
```

**Test Patterns**:
- Placeholder implementation testing
- Status validation testing
- User permission testing

---

### CRLServiceTest

**Location**: `src/test/java/com/ftn/siit/ib/public_key_infrastructure/services/CRLServiceTest.java`

**Test Coverage**:
- CRL management operations (placeholder implementations)
- Parameter validation
- Status checking
- Distribution point management

**Key Test Methods**:
```java
@Nested
@DisplayName("Generate CRL Tests")
class GenerateCRLTests {
    
    @Test
    @DisplayName("should generate CRL successfully")
    void shouldGenerateCRLSuccessfully()
    
    @Test
    @DisplayName("should throw exception when CA certificate ID is null")
    void shouldThrowExceptionWhenCACertificateIdIsNull()
}
```

**Test Patterns**:
- Placeholder implementation testing
- Parameter validation testing
- Status validation testing

## Test Patterns and Best Practices

### 1. Test Organization
- **Nested Classes**: Use `@Nested` for logical grouping of related tests
- **Display Names**: Use `@DisplayName` for readable test descriptions
- **Method Naming**: Follow "should [expected behavior] when [condition]" pattern

### 2. Mocking Strategy
- **Crypto Layer**: Direct testing without mocking (integration testing)
- **Business Logic**: Mock dependencies using `@Mock` and `@InjectMocks`
- **Repositories**: Mock all repository interactions
- **External Services**: Mock all external service calls

### 3. Test Data Management
- **Helper Methods**: Create helper methods for test data generation
- **Test Builders**: Use builder pattern for complex test objects
- **Constants**: Define test constants for reusable values

### 4. Assertion Patterns
- **Exception Testing**: Use `assertThrows` for exception validation
- **Success Testing**: Use `assertDoesNotThrow` for successful operations
- **Value Testing**: Use appropriate assertions for return values
- **State Testing**: Verify object state changes

### 5. Test Isolation
- **Independent Tests**: Each test should be independent
- **Clean Setup**: Use `@BeforeEach` for test setup
- **Clean Teardown**: Use `@AfterEach` for cleanup when needed
- **Mock Reset**: Reset mocks between tests

## Test Coverage Analysis

### Crypto Layer Coverage
- **KeyPairGeneratorService**: 100% method coverage
- **CertificateGeneratorService**: 100% method coverage
- **CertificateSignerService**: 100% method coverage
- **EncryptionService**: 100% method coverage
- **KeystoreService**: 100% method coverage
- **CRLGeneratorService**: 100% method coverage

### Business Logic Coverage
- **ValidationService**: 100% method coverage
- **CertificateService**: 12.5% method coverage (1/8 methods implemented)
- **TemplateService**: 0% method coverage (skeleton methods)
- **CSRService**: 0% method coverage (placeholder methods)
- **CRLService**: 0% method coverage (placeholder methods)

## Test Execution

### Running Tests
```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=ValidationServiceTest

# Run tests with coverage
mvn test jacoco:report

# Run tests in parallel
mvn test -T 4
```

### Test Configuration
- **JUnit 5**: Latest version with Jupiter engine
- **Mockito**: For mocking dependencies
- **AssertJ**: For fluent assertions (if used)
- **Spring Boot Test**: For integration testing

## Test Maintenance

### Adding New Tests
1. Follow the existing test structure and patterns
2. Use appropriate test annotations (`@Nested`, `@DisplayName`)
3. Mock all dependencies appropriately
4. Test both success and failure scenarios
5. Validate exception types and messages

### Updating Tests
1. Update tests when service interfaces change
2. Maintain test coverage when adding new methods
3. Update mock expectations when dependencies change
4. Refactor tests when service logic changes

### Test Quality Guidelines
- **Readable**: Tests should be self-documenting
- **Maintainable**: Tests should be easy to update
- **Reliable**: Tests should be deterministic
- **Fast**: Tests should run quickly
- **Isolated**: Tests should not depend on each other
