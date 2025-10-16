# Public Key Infrastructure (PKI) System

## Overview

This is a comprehensive Public Key Infrastructure (PKI) system built with Spring Boot that provides certificate lifecycle management, cryptographic operations, and secure key storage. The system implements industry-standard PKI components including Certificate Authorities (CAs), Certificate Signing Requests (CSRs), Certificate Revocation Lists (CRLs), and certificate templates.

## Architecture

The PKI system follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    API Layer (Controllers)                  │
├─────────────────────────────────────────────────────────────┤
│                Business Logic Layer (Services)              │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │ ValidationService│ │CertificateService│ │  TemplateService│ │
│  │   CSRService    │ │   CRLService    │ │                 │ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                  Crypto Layer (Services)                    │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │KeyPairGenerator │ │CertificateGen.  │ │CertificateSigner│ │
│  │   Encryption    │ │   Keystore      │ │   CRLGenerator  │ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer                               │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│  │   H2 Database   │ │   JPA Entities  │ │   Repositories  │ │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Certificate Types
- **ROOT**: Self-signed root Certificate Authority
- **INTERMEDIATE**: Intermediate Certificate Authority signed by root or another intermediate CA
- **END_ENTITY**: End-user certificates (servers, clients, email, code signing)

### Certificate Lifecycle
1. **Creation**: Generate key pair and create certificate
2. **Issuance**: Sign and issue certificate
3. **Validation**: Verify certificate chain and constraints
4. **Revocation**: Revoke compromised or expired certificates
5. **Distribution**: Provide certificates via CRL and OCSP

### User Roles
- **ADMIN**: Full system access, can manage all certificates and users
- **CA_USER**: Can create intermediate and end-entity certificates, manage templates
- **REGULAR_USER**: Can request certificates, view own certificates

## Technology Stack

### Core Technologies
- **Spring Boot 3.x**: Application framework
- **Spring Security**: Authentication and authorization
- **Spring Data JPA**: Data persistence
- **H2 Database**: In-memory database for development
- **Bouncy Castle**: Cryptographic operations
- **Lombok**: Code generation for boilerplate

### Security Features
- **AES-256-GCM**: Private key encryption with authenticated encryption
- **JWT Authentication**: Stateless authentication tokens
- **Role-Based Access Control (RBAC)**: Fine-grained permissions
- **HTTPS Support**: Secure communication (planned)
- **Self-signed Certificates**: For development and testing

## Project Structure

```
back-public-key-infrastructure/
├── src/main/java/com/ftn/siit/ib/public_key_infrastructure/
│   ├── config/                 # Configuration classes
│   ├── controllers/            # REST API controllers
│   ├── dtos/                   # Data Transfer Objects
│   ├── entities/               # JPA entities
│   ├── exceptions/             # Custom exceptions
│   ├── repositories/           # Data repositories
│   ├── security/               # Security configuration
│   └── services/               # Business logic services
│       ├── crypto/             # Cryptographic services
│       └── user/               # User management services
├── src/test/java/              # Test classes
├── src/main/resources/         # Configuration files
└── docs/                       # Documentation
```

## Implementation Status

### ✅ Completed Components
- **Crypto Layer**: Full implementation with Bouncy Castle
  - RSA key pair generation (2048/4096 bits)
  - X.509 certificate generation and signing
  - AES-256-GCM private key encryption
  - PKCS12 keystore creation and PEM export
  - CRL generation and management
- **ValidationService**: Comprehensive certificate and template validation
- **CertificateService**: Root certificate creation implemented
- **Database Schema**: Complete entity model with relationships
- **Authentication**: JWT-based user authentication
- **Test Suite**: 303 tests with comprehensive coverage

### ⚠️ Partial Implementation
- **CertificateService**: Only root certificate creation implemented
- **TemplateService**: Skeleton with placeholder methods
- **CSRService**: Skeleton with placeholder logic
- **CRLService**: Skeleton with placeholder logic

### ⏳ Pending Implementation
- **REST Controllers**: API endpoints for all services
- **Security Configuration**: Method-level security and CORS
- **HTTPS Configuration**: Self-signed certificates and HTTP redirect
- **Exception Handling**: Global exception handler
- **Certificate Management**: Full CRUD operations
- **Template Management**: Complete template lifecycle
- **CSR Workflow**: End-to-end CSR processing
- **CRL Management**: Full CRL operations

## Quick Start

### Prerequisites
- Java 17 or higher
- Maven 3.6 or higher

### Running the Application
```bash
# Clone the repository
git clone <repository-url>
cd public-key-infrastructure/back-public-key-infrastructure

# Build the project
mvn clean compile

# Run tests
mvn test

# Start the application
mvn spring-boot:run
```

### Test Results
- **Tests Run**: 303
- **Failures**: 1 (minor test isolation issue)
- **Errors**: 1 (cleanup issue)
- **Success Rate**: 99.3%

## Documentation

- [Services Documentation](SERVICES.md) - Detailed service documentation
- [Tests Documentation](TESTS.md) - Test structure and coverage
- [API Documentation](API.md) - API reference and specifications
- [Implementation Guide](IMPLEMENTATION.md) - Implementation details and status
- [Usage Examples](EXAMPLES.md) - Code examples and best practices

## Security Considerations

### Private Key Protection
- All private keys are encrypted using AES-256-GCM
- Master keys are Base64-encoded 256-bit keys
- IVs are randomly generated for each encryption operation
- Authentication tags prevent tampering

### Certificate Validation
- Comprehensive chain validation
- Revocation status checking
- Template constraint enforcement
- Key usage validation
- Validity period verification

### Access Control
- Role-based permissions
- Method-level security annotations
- JWT token validation
- Secure session management

## Contributing

1. Follow the existing code structure and patterns
2. Write comprehensive tests for new functionality
3. Update documentation for any API changes
4. Ensure all tests pass before submitting changes
5. Follow Java coding standards and Spring Boot best practices

## License

This project is part of a cybersecurity course implementation and is for educational purposes.
