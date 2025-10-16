package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.entities.*;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateSigningRequestRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;


import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CSRService Tests")
class CSRServiceTest {

    @Mock
    private CertificateSigningRequestRepository csrRepository;

    @Mock
    private CertificateService certificateService;

    @Mock
    private ValidationService validationService;

    private CSRService csrService;

    @BeforeEach
    void setUp() {
        csrService = new CSRService(
            csrRepository,
            certificateService,
            validationService
        );
    }

    @Nested
    @DisplayName("createCSR Tests")
    class CreateCSRTests {

              @Test
              @DisplayName("Should throw IllegalArgumentException when dto is null")
              void shouldThrowExceptionWhenDtoIsNull() {
                  // Given
                  User requester = createUser(Role.REGULAR_USER);

                  // When & Then
                  assertThrows(
                      IllegalArgumentException.class,
                      () -> csrService.createCSR(null, requester),
                      "Should throw IllegalArgumentException when DTO is null"
                  );
              }

        @Test
        @DisplayName("Should throw IllegalArgumentException when requester is null")
        void shouldThrowExceptionWhenRequesterIsNull() {
            // Given
            CreateCSRDTO dto = createCSRDTO();

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.createCSR(dto, null),
                "Should throw IllegalArgumentException when requester is null"
            );
        }

        @Test
        @DisplayName("Should create CSR successfully")
        void shouldCreateCSRSuccessfully() {
            // Given
            CreateCSRDTO dto = createCSRDTO();
            User requester = createUser(Role.REGULAR_USER);

            // When
            CSRDTO result = csrService.createCSR(dto, requester);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(1L, result.getId(), "ID should be set");
            assertEquals(CSRStatus.PENDING, result.getStatus(), "Status should be PENDING");
            assertEquals("Test Certificate", result.getSubjectCN(), "Subject CN should match");
            assertEquals("Test Organization", result.getSubjectO(), "Subject O should match");
            assertNotNull(result.getRequester(), "Requester should be set");
            assertEquals(requester.getId(), result.getRequester().getId(), "Requester ID should match");
        }
    }

    @Nested
    @DisplayName("uploadCSR Tests")
    class UploadCSRTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when dto is null")
        void shouldThrowExceptionWhenDtoIsNull() {
            // Given
            User requester = createUser(Role.REGULAR_USER);

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.uploadCSR(null, requester),
                "Should throw IllegalArgumentException when DTO is null"
            );
        }

        @Test
        @DisplayName("Should upload CSR successfully")
        void shouldUploadCSRSuccessfully() {
            // Given
            UploadCSRDTO dto = createUploadCSRDTO();
            User requester = createUser(Role.REGULAR_USER);

            // When
            CSRDTO result = csrService.uploadCSR(dto, requester);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(2L, result.getId(), "ID should be set");
            assertEquals(CSRStatus.PENDING, result.getStatus(), "Status should be PENDING");
            assertEquals("Uploaded Certificate", result.getSubjectCN(), "Subject CN should match");
            assertEquals("Uploaded Organization", result.getSubjectO(), "Subject O should match");
            assertNotNull(result.getRequester(), "Requester should be set");
            assertEquals(requester.getId(), result.getRequester().getId(), "Requester ID should match");
        }
    }

    @Nested
    @DisplayName("listUserCSRs Tests")
    class ListUserCSRsTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when user is null")
        void shouldThrowExceptionWhenUserIsNull() {
            // Given
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.listUserCSRs(null, pageable),
                "Should throw IllegalArgumentException when user is null"
            );
        }

        @Test
        @DisplayName("Should list user CSRs successfully")
        void shouldListUserCSRsSuccessfully() {
            // Given
            User user = createUser(Role.REGULAR_USER);
            Pageable pageable = mock(Pageable.class);

            // When
            Page<CSRDTO> result = csrService.listUserCSRs(user, pageable);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(0, result.getTotalElements(), "Should return empty page");
            assertTrue(result.getContent().isEmpty(), "Content should be empty");
        }
    }

    @Nested
    @DisplayName("listPendingCSRs Tests")
    class ListPendingCSRsTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when user is null")
        void shouldThrowExceptionWhenUserIsNull() {
            // Given
            Pageable pageable = mock(Pageable.class);

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.listPendingCSRs(null, pageable),
                "Should throw IllegalArgumentException when user is null"
            );
        }

        @Test
        @DisplayName("Should list pending CSRs successfully for admin")
        void shouldListPendingCSRsSuccessfullyForAdmin() {
            // Given
            User admin = createUser(Role.ADMIN);
            Pageable pageable = mock(Pageable.class);

            // When
            Page<CSRDTO> result = csrService.listPendingCSRs(admin, pageable);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(0, result.getTotalElements(), "Should return empty page");
            assertTrue(result.getContent().isEmpty(), "Content should be empty");
        }

        @Test
        @DisplayName("Should list pending CSRs successfully for CA user")
        void shouldListPendingCSRsSuccessfullyForCAUser() {
            // Given
            User caUser = createUser(Role.CA_USER);
            Pageable pageable = mock(Pageable.class);

            // When
            Page<CSRDTO> result = csrService.listPendingCSRs(caUser, pageable);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(0, result.getTotalElements(), "Should return empty page");
            assertTrue(result.getContent().isEmpty(), "Content should be empty");
        }
    }

    @Nested
    @DisplayName("approveCSR Tests")
    class ApproveCSRTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when CSR ID is null")
        void shouldThrowExceptionWhenCSRIdIsNull() {
            // Given
            User approver = createUser(Role.ADMIN);
            ApproveCSRDTO dto = new ApproveCSRDTO();

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.approveCSR(null, dto, approver),
                "Should throw IllegalArgumentException when CSR ID is null"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when approver is null")
        void shouldThrowExceptionWhenApproverIsNull() {
            // Given
            Long csrId = 1L;
            ApproveCSRDTO dto = new ApproveCSRDTO();

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.approveCSR(csrId, dto, null),
                "Should throw IllegalArgumentException when approver is null"
            );
        }

        @Test
        @DisplayName("Should approve CSR successfully")
        void shouldApproveCSRSuccessfully() {
            // Given
            Long csrId = 1L;
            User approver = createUser(Role.ADMIN);
            ApproveCSRDTO dto = new ApproveCSRDTO();

            // When
            CSRDTO result = csrService.approveCSR(csrId, dto, approver);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(csrId, result.getId(), "ID should match");
            assertEquals(CSRStatus.APPROVED, result.getStatus(), "Status should be APPROVED");
            assertNotNull(result.getProcessedAt(), "Processed at should be set");
            assertNotNull(result.getProcessedBy(), "Processed by should be set");
            assertEquals(approver.getId(), result.getProcessedBy().getId(), "Approver ID should match");
        }
    }

    @Nested
    @DisplayName("rejectCSR Tests")
    class RejectCSRTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when CSR ID is null")
        void shouldThrowExceptionWhenCSRIdIsNull() {
            // Given
            User rejector = createUser(Role.ADMIN);
            RejectCSRDTO dto = new RejectCSRDTO();

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.rejectCSR(null, dto, rejector),
                "Should throw IllegalArgumentException when CSR ID is null"
            );
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when rejector is null")
        void shouldThrowExceptionWhenRejectorIsNull() {
            // Given
            Long csrId = 1L;
            RejectCSRDTO dto = new RejectCSRDTO();

            // When & Then
            assertThrows(
                IllegalArgumentException.class,
                () -> csrService.rejectCSR(csrId, dto, null),
                "Should throw IllegalArgumentException when rejector is null"
            );
        }

        @Test
        @DisplayName("Should reject CSR successfully")
        void shouldRejectCSRSuccessfully() {
            // Given
            Long csrId = 1L;
            User rejector = createUser(Role.ADMIN);
            RejectCSRDTO dto = new RejectCSRDTO();
            dto.setReason("Invalid request");

            // When
            CSRDTO result = csrService.rejectCSR(csrId, dto, rejector);

            // Then
            assertNotNull(result, "Result should not be null");
            assertEquals(csrId, result.getId(), "ID should match");
            assertEquals(CSRStatus.REJECTED, result.getStatus(), "Status should be REJECTED");
            assertNotNull(result.getProcessedAt(), "Processed at should be set");
            assertNotNull(result.getProcessedBy(), "Processed by should be set");
            assertEquals(rejector.getId(), result.getProcessedBy().getId(), "Rejector ID should match");
            assertEquals("Invalid request", result.getRejectionReason(), "Rejection reason should match");
        }
    }

    // Helper methods
    private User createUser(Role role) {
        User user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setFirstName("Test");
        user.setLastName("User");
        user.setRole(role);
        return user;
    }

    private CreateCSRDTO createCSRDTO() {
        CreateCSRDTO dto = new CreateCSRDTO();
        dto.setSubjectCN("Test Certificate");
        dto.setSubjectO("Test Organization");
        dto.setSubjectOU("Test OU");
        dto.setSubjectL("Test City");
        dto.setSubjectST("Test State");
        dto.setSubjectC("US");
        dto.setSubjectE("test@example.com");
        dto.setKeySize(2048);
        return dto;
    }

    private UploadCSRDTO createUploadCSRDTO() {
        UploadCSRDTO dto = new UploadCSRDTO();
        // Add fields as needed when UploadCSRDTO is properly defined
        return dto;
    }
}
