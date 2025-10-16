package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateSigningRequest;
import com.ftn.siit.ib.public_key_infrastructure.entities.CSRStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
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
    
    // Find CSRs by status
    List<CertificateSigningRequest> findByStatus(CSRStatus status);
    
    // Find CSRs by requester and status
    List<CertificateSigningRequest> findByRequesterAndStatus(User requester, CSRStatus status);
    
    // Find pending CSRs for a specific CA (by selected CA)
    List<CertificateSigningRequest> findBySelectedCAAndStatus(User selectedCA, CSRStatus status);
    
    // Find CSRs by selected CA
    List<CertificateSigningRequest> findBySelectedCA(User selectedCA);
    
    // Find CSRs by selected CA's organization (for CA users)
    @Query("SELECT csr FROM CertificateSigningRequest csr WHERE csr.selectedCA.owner.organization.id = :organizationId")
    List<CertificateSigningRequest> findBySelectedCAOrganization(@Param("organizationId") Long organizationId);
    
    // Find pending CSRs by selected CA's organization
    @Query("SELECT csr FROM CertificateSigningRequest csr WHERE csr.selectedCA.owner.organization.id = :organizationId AND csr.status = 'PENDING'")
    List<CertificateSigningRequest> findPendingBySelectedCAOrganization(@Param("organizationId") Long organizationId);
    
    // Find CSRs by processed by user
    List<CertificateSigningRequest> findByProcessedBy(User processedBy);
    
    // Find CSR by issued certificate
    Optional<CertificateSigningRequest> findByIssuedCertificateId(Long issuedCertificateId);
    
    // Check if CSR exists for a requester with specific subject CN
    boolean existsByRequesterAndSubjectCN(User requester, String subjectCN);
}
