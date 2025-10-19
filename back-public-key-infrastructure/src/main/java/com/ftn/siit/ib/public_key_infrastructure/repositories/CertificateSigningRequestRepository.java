package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateSigningRequest;
import com.ftn.siit.ib.public_key_infrastructure.entities.CSRStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateSigningRequestRepository extends JpaRepository<CertificateSigningRequest, Long> {
    
    // Find CSRs by requester
    List<CertificateSigningRequest> findByRequester(User requester);
    
    // Find CSRs by requester with pagination
    Page<CertificateSigningRequest> findByRequester(User requester, Pageable pageable);
    
    // Find CSRs by status
    List<CertificateSigningRequest> findByStatus(CSRStatus status);
    
    // Find CSRs by status with pagination
    Page<CertificateSigningRequest> findByStatus(CSRStatus status, Pageable pageable);
    
    // Find CSRs by requester and status
    List<CertificateSigningRequest> findByRequesterAndStatus(User requester, CSRStatus status);
    
    // Find pending CSRs for a specific CA (by selected CA)
    List<CertificateSigningRequest> findBySelectedCAAndStatus(Certificate selectedCA, CSRStatus status);

    // Find pending CSRs for a specific CA (by selected CA) with pagination
    Page<CertificateSigningRequest> findBySelectedCAAndStatus(Certificate selectedCA, CSRStatus status, Pageable pageable);

    // Find CSRs by selected CA
    List<CertificateSigningRequest> findBySelectedCA(Certificate selectedCA);

    // Find CSRs by request target
    List<CertificateSigningRequest> findByRequestedFor(User requestedFor);
    List<CertificateSigningRequest> findByRequestedFrom(User requestedFrom);
    
    // Find CSRs by selected CA's organization (for CA users) - using many-to-many relationship
    @Query("SELECT csr FROM CertificateSigningRequest csr WHERE csr.selectedCA IN (SELECT c FROM User u JOIN u.myCertificates c WHERE u.organization = :organizationName)")
    List<CertificateSigningRequest> findBySelectedCAOrganization(@Param("organizationName") String organizationName);
    
    // Find pending CSRs by selected CA's organization - using many-to-many relationship
    @Query("SELECT csr FROM CertificateSigningRequest csr WHERE csr.selectedCA IN (SELECT c FROM User u JOIN u.myCertificates c WHERE u.organization = :organizationName) AND csr.status = 'PENDING'")
    List<CertificateSigningRequest> findPendingBySelectedCAOrganization(@Param("organizationName") String organizationName);
    
    // Find CSRs by processed by user
    List<CertificateSigningRequest> findByProcessedBy(User processedBy);
    
    // Find CSR by issued certificate
    Optional<CertificateSigningRequest> findByIssuedCertificateId(Long issuedCertificateId);
    
    // Check if CSR exists for a requester with specific subject CN
    boolean existsByRequesterAndSubjectCN(User requester, String subjectCN);
}
