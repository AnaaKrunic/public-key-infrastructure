package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
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
public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    
    // Find by serial number
    Optional<Certificate> findBySerialNumber(String serialNumber);
    
    // Find by owner
    List<Certificate> findByOwner(User owner);
    Page<Certificate> findByOwner(User owner, Pageable pageable);
    
    // Find by status
    List<Certificate> findByStatus(CertificateStatus status);
    Page<Certificate> findByStatus(CertificateStatus status, Pageable pageable);
    
    // Find by type
    List<Certificate> findByCertificateType(CertificateType certificateType);
    Page<Certificate> findByCertificateType(CertificateType certificateType, Pageable pageable);
    
    // Find by owner and status
    List<Certificate> findByOwnerAndStatus(User owner, CertificateStatus status);
    Page<Certificate> findByOwnerAndStatus(User owner, CertificateStatus status, Pageable pageable);
    
    // Find by owner and type
    List<Certificate> findByOwnerAndCertificateType(User owner, CertificateType certificateType);
    Page<Certificate> findByOwnerAndCertificateType(User owner, CertificateType certificateType, Pageable pageable);
    
    // Find by issuer certificate (for building chains)
    List<Certificate> findByIssuerCertificate(Certificate issuerCertificate);
    
    // Find CA certificates (Root and Intermediate)
    @Query("SELECT c FROM Certificate c WHERE c.certificateType IN ('ROOT', 'INTERMEDIATE')")
    List<Certificate> findCACertificates();
    
    // Find CA certificates by owner
    @Query("SELECT c FROM Certificate c WHERE c.owner = :owner AND c.certificateType IN ('ROOT', 'INTERMEDIATE')")
    List<Certificate> findCACertificatesByOwner(@Param("owner") User owner);
    
    // Find certificates in a chain (from a specific CA down to end-entities)
    @Query("SELECT c FROM Certificate c WHERE c.issuerCertificate = :ca OR c.issuerCertificate IN " +
           "(SELECT c2 FROM Certificate c2 WHERE c2.issuerCertificate = :ca)")
    List<Certificate> findCertificatesInChain(@Param("ca") Certificate ca);
    
    // Find certificates by owner's organization (for CA users)
    @Query("SELECT c FROM Certificate c WHERE c.owner.organization = :organizationId")
    List<Certificate> findByOwnerOrganization(@Param("organizationId") Long organizationId);
    Page<Certificate> findByOwnerOrganization(@Param("organizationId") Long organizationId, Pageable pageable);
    
    // Find certificates by owner's organization and status
    @Query("SELECT c FROM Certificate c WHERE c.owner.organization.id = :organizationId AND c.status = :status")
    List<Certificate> findByOwnerOrganizationAndStatus(@Param("organizationId") Long organizationId, 
                                                      @Param("status") CertificateStatus status);
    Page<Certificate> findByOwnerOrganizationAndStatus(@Param("organizationId") Long organizationId, 
                                                      @Param("status") CertificateStatus status, 
                                                      Pageable pageable);
    
    // Find certificates by owner's organization and type
    @Query("SELECT c FROM Certificate c WHERE c.owner.organization.id = :organizationId AND c.certificateType = :type")
    List<Certificate> findByOwnerOrganizationAndType(@Param("organizationId") Long organizationId, 
                                                    @Param("type") CertificateType type);
    Page<Certificate> findByOwnerOrganizationAndType(@Param("organizationId") Long organizationId, 
                                                    @Param("type") CertificateType type, 
                                                    Pageable pageable);
    
    // Check if certificate exists by serial number
    boolean existsBySerialNumber(String serialNumber);
    
    // Find revoked certificates for CRL generation
    @Query("SELECT c FROM Certificate c WHERE c.status = 'REVOKED' AND c.issuerCertificate = :issuer")
    List<Certificate> findRevokedCertificatesByIssuer(@Param("issuer") Certificate issuer);
}
