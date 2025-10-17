# Complete PKI System Implementation Plan
*Based on reference .NET implementation patterns adapted for Java/Spring Boot*

## Phase 1: Data Model & Repository Enhancements

### 1.1 Update Organization Entity

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/entities/Organization.java`

- Add fields: `description`, `contactEmail`, `contactPhone`, `address`, `createdAt`, `updatedAt`
- Keep simple structure for organization management
- Reference pattern: Similar to .NET User.Organization field

### 1.2 Update Certificate Entity

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/entities/Certificate.java`

- Add `organization` field with `@ManyToOne` relationship to Organization entity
- Add `signedBy` field with `@ManyToOne` relationship to User entity (who issued the certificate)
- Add `pathLen` field (int) for path length constraints
- Add `canSign` field (boolean) to indicate if certificate can be used for signing
- JPA will handle the foreign key mapping automatically
- Reference pattern: Similar to .NET Certificate.SignedBy and Certificate.CanSign

### 1.3 Update CertificateTemplate Entity

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/entities/CertificateTemplate.java`

- Add `owner` field with `@ManyToOne` relationship to User entity (personal templates)
- Add `organization` field with `@ManyToOne` relationship to Organization entity
- JPA will handle foreign key relationships automatically

### 1.4 Add Repository Methods

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/repositories/UserRepository.java`

- Add: `long countByOrganization(Organization org)`
- Add: `List<User> findByRole(Role role)`
- Add: `List<User> findByOrganizationAndRole(Organization org, Role role)`

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/repositories/CertificateRepository.java`

- Add: `long countByOwner_Organization(Organization org)`
- Add: `List<Certificate> findByOrganizationAndCertificateTypeIn(Organization org, List<CertificateType> types)`

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/repositories/CertificateTemplateRepository.java`

- Add: `List<CertificateTemplate> findByOwner(User owner)`
- Add: `Optional<CertificateTemplate> findByIdAndOwner(Long id, User owner)`

## Phase 2: DTOs for New Functionality

### 2.1 Organization Management DTOs

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/dtos/OrganizationDTO.java`

```java
- Long id
- String name (required, unique)
- String description
- String contactEmail
- String contactPhone
- String address
- int userCount (computed)
- int certificateCount (computed)
```

### 2.2 Admin User Management DTOs

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/dtos/CreateCAUserDTO.java`

```java
- String email (required, unique)
- String password (required, min 8 chars)
- String firstName (required)
- String lastName (required)
- Long organizationId (required)
```

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/dtos/UserDTO.java`

```java
- Long id
- String email
- String firstName
- String lastName
- Role role
- String organizationName
- Long organizationId
- boolean enabled
- boolean mfaEnabled
```

### 2.3 Certificate Assignment DTO

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/dtos/AssignCACertificateDTO.java`

```java
- String certificateSerialNumber (CA cert to assign)
- Long organizationId (organization receiving the CA)
```

## Phase 3: Service Layer Implementation

### 3.1 OrganizationService

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/services/OrganizationService.java`

Methods:

- `OrganizationDTO createOrganization(OrganizationDTO dto)` - Admin only
- `OrganizationDTO updateOrganization(Long id, OrganizationDTO dto)` - Admin only
- `void deleteOrganization(Long id)` - Admin only, check no users exist
- `OrganizationDTO getOrganizationById(Long id)`
- `Page<OrganizationDTO> listOrganizations(Pageable pageable)` - Admin sees all
- `List<OrganizationDTO> listAllOrganizations()` - For dropdowns

### 3.2 AdminUserService

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/services/AdminUserService.java`

Methods:

- `UserDTO createCAUser(CreateCAUserDTO dto)` - Creates CA_USER, sends activation email
- `UserDTO getUserById(Long id)`
- `Page<UserDTO> listAllUsers(Pageable pageable)` - Admin sees all users
- `Page<UserDTO> listCAUsers(Pageable pageable)` - Filter by CA_USER role
- `Page<UserDTO> listUsersByOrganization(Organization org, Pageable pageable)`
- `void deleteUser(Long id)` - Admin only, check no certificates exist
- `UserDTO promoteToCAUser(Long userId, Organization organization)` - Change REGULAR_USER to CA_USER
- `UserDTO demoteToRegularUser(Long userId)` - Change CA_USER to REGULAR_USER

### 3.3 Update CertificateService

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/services/CertificateService.java`

Modifications:

- In `createRootCertificate()`: Set `organization` from admin's input
- In `createIntermediateCertificate()`: Set `organization` from issuer CA's organization
- In `createEndEntityCertificate()`: Set `organization` from issuer CA's organization
- Update `listCertificates()` authorization:
  - ADMIN: sees all certificates
  - CA_USER: sees only certificates where `owner = user OR issuerCert.organization = user.organization`
  - REGULAR_USER: sees only own certificates
- Add method: `List<CertificateDTO> getAvailableCACertificates(User user)`
  - ADMIN: all ROOT and INTERMEDIATE certs
  - CA_USER: only certs where `organization = user.organization AND type IN (ROOT, INTERMEDIATE)`
  - REGULAR_USER: all ROOT and INTERMEDIATE certs (for CSR selection)

### 3.4 Update TemplateService

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/services/TemplateService.java`

Modifications:

- In `createTemplate()`: Set `owner` to current user, set `organization`
- In `listTemplates()`: Filter by `owner = currentUser` (personal templates)
- In `updateTemplate()`: Check `owner = currentUser` before allowing update
- In `deleteTemplate()`: Check `owner = currentUser` before allowing delete
- Templates are personal - each CA user manages their own

### 3.5 Update CSRService

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/services/CSRService.java`

Modifications:

- In `createCSR()`: Allow user to specify `selectedCA` from available CA certificates
- In `uploadCSR()`: Parse CSR (no private key upload per standard practice), allow CA selection
- In `approveCSR()`: 
  - Check if approver has permission (ADMIN or CA_USER with matching organization)
  - Issue certificate using selected CA
  - Link issued certificate to requester

## Phase 4: REST API Controllers

### 4.1 OrganizationController (Admin Only)

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/OrganizationController.java`

Endpoints:

- `POST /api/organizations` - Create organization
- `GET /api/organizations` - List all organizations (paginated)
- `GET /api/organizations/{id}` - Get organization details
- `PUT /api/organizations/{id}` - Update organization
- `DELETE /api/organizations/{id}` - Delete organization
- `GET /api/organizations/all` - Get all organizations (for dropdowns)

All endpoints: `@PreAuthorize("hasRole('ADMIN')")`

### 4.2 AdminUserController (Admin Only)

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/AdminUserController.java`

Endpoints:

- `POST /api/admin/users/ca` - Create CA user
- `GET /api/admin/users` - List all users (paginated)
- `GET /api/admin/users/ca` - List CA users only
- `GET /api/admin/users/organization/{orgId}` - List users by organization
- `GET /api/admin/users/{id}` - Get user details
- `DELETE /api/admin/users/{id}` - Delete user
- `PUT /api/admin/users/{id}/promote` - Promote to CA_USER
- `PUT /api/admin/users/{id}/demote` - Demote to REGULAR_USER

All endpoints: `@PreAuthorize("hasRole('ADMIN')")`

### 4.3 CertificateController

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/CertificateController.java`

Endpoints:

- `POST /api/certificates/root` - Create ROOT certificate (ADMIN only)
- `POST /api/certificates/intermediate` - Create INTERMEDIATE (ADMIN or CA_USER)
- `POST /api/certificates/end-entity` - Create END_ENTITY (ADMIN or CA_USER)
- `GET /api/certificates` - List certificates (filtered by role)
- `GET /api/certificates/{serialNumber}` - Get certificate details
- `GET /api/certificates/{serialNumber}/chain` - Get certificate chain
- `GET /api/certificates/{serialNumber}/download` - Download certificate (PEM/PKCS12)
- `POST /api/certificates/{serialNumber}/revoke` - Revoke certificate
- `GET /api/certificates/available-cas` - Get available CA certificates for user

Authorization per endpoint based on user role.

### 4.4 TemplateController (CA_USER only)

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/TemplateController.java`

Endpoints:

- `POST /api/templates` - Create template
- `GET /api/templates` - List user's templates
- `GET /api/templates/{id}` - Get template details
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template

All endpoints: `@PreAuthorize("hasRole('CA_USER')")`

### 4.5 CSRController

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/CSRController.java`

Endpoints:

- `POST /api/csr/create` - Auto-generate CSR + key pair (REGULAR_USER)
- `POST /api/csr/upload` - Upload external CSR (REGULAR_USER)
- `GET /api/csr` - List user's CSRs
- `GET /api/csr/pending` - List pending CSRs (CA_USER, ADMIN)
- `GET /api/csr/{id}` - Get CSR details
- `POST /api/csr/{id}/approve` - Approve CSR (CA_USER, ADMIN)
- `POST /api/csr/{id}/reject` - Reject CSR (CA_USER, ADMIN)

Authorization per endpoint based on user role.

### 4.6 Update AuthController

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/AuthController.java`

Ensure endpoints exist:

- `POST /api/auth/register` - User registration
- `GET /api/auth/activate?token=xxx` - Account activation
- `POST /api/auth/login` - Login
- `POST /api/auth/refresh` - Refresh token
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Get current user info

## Phase 5: Security & HTTPS Configuration

### 5.1 Update SecurityConfig

**File**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/config/SecurityConfig.java`

Updates:

- Configure HTTP to HTTPS redirect
- Set up JWT authentication filter
- Configure endpoint authorization:
  - `/api/auth/register`, `/api/auth/activate`, `/api/auth/login` - permit all
  - `/api/admin/**` - ADMIN only
  - `/api/organizations/**` - ADMIN only
  - `/api/certificates/**` - authenticated users (role-based checks in controllers)
  - `/api/templates/**` - CA_USER only
  - `/api/csr/**` - authenticated users

### 5.2 Generate Self-Signed Certificate for HTTPS

**File**: `back-public-key-infrastructure/src/main/resources/application.properties`

Add configuration:

```properties
# HTTPS Configuration
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=changeit
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=tomcat

# HTTP to HTTPS redirect
server.http.port=8080
```

Create keystore using keytool command (documented in README).

### 5.3 Add GlobalExceptionHandler

**Create**: `back-public-key-infrastructure/src/main/java/com/ftn/siit/ib/public_key_infrastructure/controllers/GlobalExceptionHandler.java`

Handle exceptions:

- `NotFoundException` → 404
- `UnauthorizedException` → 401
- `ForbiddenException` → 403
- `IllegalArgumentException` → 400
- `IllegalStateException` → 409
- `ValidationException` → 400
- Generic exceptions → 500

Return consistent error response format:

```json
{
  "timestamp": "2025-01-16T10:30:00",
  "status": 400,
  "error": "Bad Request",
  "message": "Certificate with serial number X already exists",
  "path": "/api/certificates"
}
```

## Phase 6: Database Initialization

### 6.1 Update data.sql

**File**: `back-public-key-infrastructure/src/main/resources/data.sql`

Add seed data:

```sql
-- Insert default admin user
INSERT INTO users (email, password_hash, first_name, last_name, role, enabled, mfa_enabled)
VALUES ('admin@pki.local', '$2a$10$...', 'System', 'Administrator', 'ADMIN', true, false);

-- Insert sample organizations
INSERT INTO organizations (name, description, contact_email, created_at)
VALUES 
  ('PKI Root Authority', 'Root certificate authority', 'root@pki.local', CURRENT_TIMESTAMP),
  ('Example Corp', 'Example corporation', 'contact@example.com', CURRENT_TIMESTAMP);

-- Insert sample CA user
INSERT INTO users (email, password_hash, first_name, last_name, role, organization_id, enabled, mfa_enabled)
VALUES ('ca@example.com', '$2a$10$...', 'CA', 'User', 'CA_USER', 2, true, false);
```

## Phase 7: Testing & Documentation

### 7.1 Fix Remaining Test Failures

- Fix `CertificateServiceTest` compilation errors
- Fix `CertificateGeneratorServiceTest` email validation
- Fix `PublicKeyInfrastructureApplicationTests` context loading

### 7.2 Add Integration Tests

**Create**: Test files for new controllers

- `OrganizationControllerTest`
- `AdminUserControllerTest`
- `CertificateControllerTest`
- `TemplateControllerTest`
- `CSRControllerTest`

### 7.3 Update Documentation

**Create**: `back-public-key-infrastructure/README.md`

Document:

- System architecture
- User roles and permissions
- API endpoints
- HTTPS setup instructions
- Database initialization
- Running the application
- Default admin credentials

## Phase 8: Frontend Integration (Optional - if time permits)

### 8.1 Update Angular Services

**Directory**: `front-public-key-infrastructure/src/app/`

Create services:

- `organization.service.ts`
- `admin-user.service.ts`
- `certificate.service.ts`
- `template.service.ts`
- `csr.service.ts`

### 8.2 Create Components

- Admin dashboard (organization & user management)
- CA user dashboard (certificate issuance, template management)
- Regular user dashboard (CSR upload, certificate requests)
- Certificate viewer
- Template editor

## Summary

This plan implements a complete PKI system with:

- **Admin**: Full system control, organization management, CA user creation, ROOT CA issuance
- **CA User**: Organization-specific certificate issuance (INTERMEDIATE + END_ENTITY), personal templates
- **Regular User**: CSR upload/generation, certificate requests, certificate download

The implementation follows security best practices with HTTPS, JWT authentication, role-based access control, and proper private key handling (never upload private keys).

### Key Patterns from Reference Implementation

1. **Entity Relationships**: Use JPA `@ManyToOne` relationships instead of IDs for better type safety
2. **Role-Based Access**: Similar to .NET's Role enum (Admin, CaUser, EeUser)
3. **Certificate Chain Management**: Track `signedBy` and `issuerCertificate` relationships
4. **Organization-Based Filtering**: CA users can only access certificates from their organization
5. **Personal Templates**: Each CA user manages their own certificate templates
6. **Standard CSR Workflow**: Upload CSR only, never private keys (security best practice)

### To-dos

- [x] Create docs/README.md with system overview, architecture, and key concepts
- [x] Create docs/SERVICES.md documenting all crypto and business logic services
- [x] Create docs/TESTS.md with test structure, coverage, and statistics
- [x] Create docs/API.md with API reference for all services
- [x] Create docs/IMPLEMENTATION.md with implementation details and status
- [x] Create docs/EXAMPLES.md with usage examples and code snippets
