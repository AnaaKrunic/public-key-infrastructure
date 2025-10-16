# Usage Examples

This document provides comprehensive code examples for using the PKI system, including crypto layer operations, validation, certificate management, and best practices.

## Crypto Layer Examples

### 1. Generate RSA Key Pair

```java
@Autowired
private KeyPairGeneratorService keyPairGeneratorService;

public void generateKeyPair() {
    // Generate 2048-bit RSA key pair
    KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
    
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();
    
    System.out.println("Key pair generated successfully");
    System.out.println("Private key algorithm: " + privateKey.getAlgorithm());
    System.out.println("Public key algorithm: " + publicKey.getAlgorithm());
}
```

### 2. Build X.500 Distinguished Name

```java
@Autowired
private CertificateGeneratorService certificateGeneratorService;

public void buildDistinguishedName() {
    X500Name subjectDN = certificateGeneratorService.buildX500Name(
        "My Root CA",           // Common Name
        "My Organization",      // Organization
        "IT Department",        // Organizational Unit
        "Belgrade",            // Locality
        "Serbia",              // State
        "RS",                  // Country (2-letter ISO code)
        "admin@example.com"    // Email
    );
    
    System.out.println("Distinguished Name: " + subjectDN.toString());
}
```

### 3. Generate Root Certificate

```java
@Autowired
private CertificateGeneratorService certificateGeneratorService;

@Autowired
private KeyPairGeneratorService keyPairGeneratorService;

public void generateRootCertificate() {
    // Generate key pair
    KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
    
    // Build subject DN
    X500Name subjectDN = certificateGeneratorService.buildX500Name(
        "My Root CA",
        "My Organization",
        "IT Department",
        "Belgrade",
        "Serbia",
        "RS",
        "admin@example.com"
    );
    
    // Define key usage
    List<String> keyUsage = Arrays.asList("keyCertSign", "cRLSign");
    
    // Generate root certificate
    X509Certificate rootCert = certificateGeneratorService.generateRootCertificate(
        keyPair,
        subjectDN,
        3650,  // 10 years validity
        keyUsage,
        null   // Unlimited path length
    );
    
    System.out.println("Root certificate generated: " + rootCert.getSerialNumber());
}
```

### 4. Encrypt Private Key

```java
@Autowired
private EncryptionService encryptionService;

public void encryptPrivateKey() {
    // Generate key pair
    KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
    
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

### 5. Create PKCS12 Keystore

```java
@Autowired
private KeystoreService keystoreService;

public void createKeystore() {
    // Generate key pair and certificate (simplified)
    KeyPair keyPair = keyPairGeneratorService.generateKeyPair(2048);
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

### 6. Generate CRL

```java
@Autowired
private CRLGeneratorService crlGeneratorService;

public void generateCRL() {
    // Get CA certificate and private key
    X509Certificate caCert = getCACertificate();
    PrivateKey caPrivateKey = getCAPrivateKey();
    
    // List of revoked certificate serial numbers
    List<BigInteger> revokedSerials = Arrays.asList(
        BigInteger.valueOf(12345),
        BigInteger.valueOf(67890)
    );
    
    // Generate CRL
    X509CRL crl = crlGeneratorService.generateCRL(
        caCert,
        caPrivateKey,
        revokedSerials,
        "http://crl.example.com/crl.pem"
    );
    
    System.out.println("CRL generated successfully");
    System.out.println("Revoked certificates: " + crl.getRevokedCertificates().size());
}
```

## Validation Examples

### 1. Validate Certificate

```java
@Autowired
private ValidationService validationService;

public void validateCertificate() {
    Certificate certificate = getCertificate();
    
    try {
        validationService.validateIssuerCertificate(certificate);
        System.out.println("Certificate is valid");
    } catch (InvalidCertificateException e) {
        System.out.println("Certificate validation failed: " + e.getMessage());
    }
}
```

### 2. Validate Certificate Chain

```java
@Autowired
private ValidationService validationService;

public void validateCertificateChain() {
    // Build certificate chain
    List<Certificate> chain = buildCertificateChain();
    
    try {
        validationService.validateCertificateChain(chain);
        System.out.println("Certificate chain is valid");
    } catch (InvalidCertificateChainException e) {
        System.out.println("Chain validation failed: " + e.getMessage());
    }
}
```

### 3. Validate Template Constraints

```java
@Autowired
private ValidationService validationService;

public void validateTemplateConstraints() {
    CreateEndEntityCertificateDTO request = new CreateEndEntityCertificateDTO();
    request.setSubjectCN("server.example.com");
    request.setValidityDays(365);
    
    CertificateTemplate template = getTemplate();
    
    try {
        validationService.validateTemplateConstraints(request, template);
        System.out.println("Request meets template constraints");
    } catch (TemplateConstraintViolationException e) {
        System.out.println("Template constraint violation: " + e.getMessage());
    }
}
```

## Certificate Management Examples

### 1. Create Root Certificate

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

### 2. List Certificates

```java
@Autowired
private CertificateService certificateService;

public void listCertificates() {
    User user = getCurrentUser();
    Pageable pageable = PageRequest.of(0, 10);
    
    Page<CertificateDTO> certificates = certificateService.listCertificates(
        CertificateType.END_ENTITY,
        CertificateStatus.VALID,
        pageable,
        user
    );
    
    System.out.println("Found " + certificates.getTotalElements() + " certificates");
    for (CertificateDTO cert : certificates.getContent()) {
        System.out.println("Certificate: " + cert.getSerialNumber() + 
                          " - " + cert.getSubjectCN());
    }
}
```

### 3. Download Certificate

```java
@Autowired
private CertificateService certificateService;

public void downloadCertificate() {
    String serialNumber = "12345";
    User user = getCurrentUser();
    
    // Download as PEM format
    byte[] pemData = certificateService.downloadCertificate(
        serialNumber,
        "PEM",
        null,
        user
    );
    
    // Save to file
    try (FileOutputStream fos = new FileOutputStream("certificate.pem")) {
        fos.write(pemData);
    }
    
    System.out.println("Certificate downloaded successfully");
}
```

## Error Handling Examples

### 1. Handle Validation Exceptions

```java
public void handleValidationErrors() {
    try {
        validationService.validateIssuerCertificate(certificate);
    } catch (InvalidCertificateException e) {
        if (e.getMessage().contains("expired")) {
            System.out.println("Certificate has expired");
        } else if (e.getMessage().contains("revoked")) {
            System.out.println("Certificate has been revoked");
        } else {
            System.out.println("Certificate validation failed: " + e.getMessage());
        }
    } catch (ValidationException e) {
        System.out.println("Validation error: " + e.getMessage());
    }
}
```

### 2. Handle Permission Exceptions

```java
public void handlePermissionErrors() {
    try {
        certificateService.revokeCertificate(serialNumber, dto, user);
    } catch (UnauthorizedException e) {
        System.out.println("Access denied: " + e.getMessage());
    } catch (NotFoundException e) {
        System.out.println("Certificate not found: " + e.getMessage());
    }
}
```

## Best Practices

### 1. Key Management

```java
public class KeyManagementBestPractices {
    
    // Use strong master keys
    public String generateStrongMasterKey() {
        byte[] keyBytes = new byte[32]; // 256 bits
        new SecureRandom().nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }
    
    // Rotate master keys regularly
    public void rotateMasterKey() {
        String newMasterKey = generateStrongMasterKey();
        // Update master key in secure storage
        updateMasterKeyInStorage(newMasterKey);
    }
    
    // Validate key strength
    public boolean isKeyStrong(String key) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            return keyBytes.length == 32; // 256 bits
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
```

### 2. Certificate Validation

```java
public class CertificateValidationBestPractices {
    
    // Always validate certificate chain
    public boolean validateCertificateChain(String serialNumber) {
        try {
            List<Certificate> chain = buildCertificateChain(serialNumber);
            validationService.validateCertificateChain(chain);
            return true;
        } catch (InvalidCertificateChainException e) {
            log.error("Certificate chain validation failed", e);
            return false;
        }
    }
    
    // Check revocation status
    public boolean isCertificateRevoked(String serialNumber) {
        try {
            return crlService.checkRevocationStatus(serialNumber, caCertificateId);
        } catch (Exception e) {
            log.error("Failed to check revocation status", e);
            return true; // Assume revoked if check fails
        }
    }
}
```

### 3. Security Considerations

```java
public class SecurityBestPractices {
    
    // Validate user permissions
    public void validateUserPermissions(User user, String operation) {
        if (user == null) {
            throw new UnauthorizedException("User not authenticated");
        }
        
        if (!user.hasPermission(operation)) {
            throw new UnauthorizedException("User lacks permission for: " + operation);
        }
    }
    
    // Sanitize input data
    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        return input.trim().replaceAll("[^a-zA-Z0-9@._-]", "");
    }
    
    // Log security events
    public void logSecurityEvent(String event, User user, String details) {
        log.info("Security event: {} by user: {} - {}", event, user.getEmail(), details);
    }
}
```

## Integration Examples

### 1. Spring Boot Configuration

```java
@Configuration
@EnableJpaRepositories
public class PKIConfiguration {
    
    @Bean
    public KeyPairGeneratorService keyPairGeneratorService() {
        return new KeyPairGeneratorService();
    }
    
    @Bean
    public CertificateGeneratorService certificateGeneratorService() {
        return new CertificateGeneratorService();
    }
    
    @Bean
    public EncryptionService encryptionService() {
        return new EncryptionService();
    }
}
```

### 2. REST Controller Example

```java
@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
    
    @Autowired
    private CertificateService certificateService;
    
    @PostMapping("/root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CertificateDTO> createRootCertificate(
            @RequestBody CreateRootCertificateDTO dto,
            Authentication authentication) {
        
        User user = (User) authentication.getPrincipal();
        CertificateDTO certificate = certificateService.createRootCertificate(dto, user);
        
        return ResponseEntity.ok(certificate);
    }
    
    @GetMapping("/{serialNumber}")
    @PreAuthorize("hasRole('ADMIN') or @certificateService.isOwner(#serialNumber, authentication.name)")
    public ResponseEntity<CertificateDTO> getCertificate(
            @PathVariable String serialNumber,
            Authentication authentication) {
        
        User user = (User) authentication.getPrincipal();
        CertificateDTO certificate = certificateService.getCertificateBySerialNumber(serialNumber, user);
        
        return ResponseEntity.ok(certificate);
    }
}
```

### 3. Exception Handler

```java
@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(InvalidCertificateException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCertificate(InvalidCertificateException e) {
        ErrorResponse error = new ErrorResponse(
            HttpStatus.BAD_REQUEST.value(),
            "Invalid Certificate",
            e.getMessage()
        );
        return ResponseEntity.badRequest().body(error);
    }
    
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(UnauthorizedException e) {
        ErrorResponse error = new ErrorResponse(
            HttpStatus.UNAUTHORIZED.value(),
            "Unauthorized",
            e.getMessage()
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }
}
```

## Testing Examples

### 1. Unit Test Example

```java
@ExtendWith(MockitoExtension.class)
class CertificateServiceTest {
    
    @Mock
    private ValidationService validationService;
    
    @Mock
    private KeyPairGeneratorService keyPairGeneratorService;
    
    @InjectMocks
    private CertificateService certificateService;
    
    @Test
    void shouldCreateRootCertificateSuccessfully() {
        // Given
        CreateRootCertificateDTO dto = createValidRootCertificateDTO();
        User admin = createAdminUser();
        
        when(keyPairGeneratorService.generateKeyPair(anyInt())).thenReturn(createKeyPair());
        
        // When
        CertificateDTO result = certificateService.createRootCertificate(dto, admin);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getSerialNumber()).isNotEmpty();
        assertThat(result.getCertificateType()).isEqualTo(CertificateType.ROOT);
    }
}
```

### 2. Integration Test Example

```java
@SpringBootTest
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
class CertificateServiceIntegrationTest {
    
    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    @Transactional
    void shouldCreateAndRetrieveRootCertificate() {
        // Given
        User admin = createAndSaveAdminUser();
        CreateRootCertificateDTO dto = createValidRootCertificateDTO();
        
        // When
        CertificateDTO created = certificateService.createRootCertificate(dto, admin);
        CertificateDTO retrieved = certificateService.getCertificateBySerialNumber(
            created.getSerialNumber(), admin);
        
        // Then
        assertThat(retrieved).isNotNull();
        assertThat(retrieved.getSerialNumber()).isEqualTo(created.getSerialNumber());
    }
}
```

## Performance Optimization Examples

### 1. Batch Operations

```java
public class BatchOperations {
    
    @Autowired
    private CertificateService certificateService;
    
    @Async
    public CompletableFuture<List<CertificateDTO>> createCertificatesBatch(
            List<CreateEndEntityCertificateDTO> requests) {
        
        List<CertificateDTO> results = new ArrayList<>();
        
        for (CreateEndEntityCertificateDTO request : requests) {
            try {
                CertificateDTO certificate = certificateService.createEndEntityCertificate(
                    request, getCurrentUser());
                results.add(certificate);
            } catch (Exception e) {
                log.error("Failed to create certificate for: " + request.getSubjectCN(), e);
            }
        }
        
        return CompletableFuture.completedFuture(results);
    }
}
```

### 2. Caching Example

```java
@Service
public class CachedCertificateService {
    
    @Autowired
    private CertificateService certificateService;
    
    @Cacheable(value = "certificates", key = "#serialNumber")
    public CertificateDTO getCertificateBySerialNumber(String serialNumber, User user) {
        return certificateService.getCertificateBySerialNumber(serialNumber, user);
    }
    
    @CacheEvict(value = "certificates", key = "#serialNumber")
    public void evictCertificateCache(String serialNumber) {
        // Cache eviction handled by annotation
    }
}
```

These examples demonstrate the comprehensive usage of the PKI system, from basic cryptographic operations to advanced integration patterns and best practices.
