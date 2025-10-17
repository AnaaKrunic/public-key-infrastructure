package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateType;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.entities.Organization;
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
    
    // Find by owner - using many-to-many relationship
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner")
    List<Certificate> findByOwner(@Param("owner") User owner);
    
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner")
    Page<Certificate> findByOwner(@Param("owner") User owner, Pageable pageable);

    // Find by signer
    List<Certificate> findBySignedBy(User signedBy);
    Page<Certificate> findBySignedBy(User signedBy, Pageable pageable);

    // Find by signing organization
    List<Certificate> findBySigningOrganization(Organization signingOrganization);
    Page<Certificate> findBySigningOrganization(Organization signingOrganization, Pageable pageable);
    
    // Find by status
    List<Certificate> findByStatus(CertificateStatus status);
    Page<Certificate> findByStatus(CertificateStatus status, Pageable pageable);
    
    // Find by type
    List<Certificate> findByCertificateType(CertificateType certificateType);
    Page<Certificate> findByCertificateType(CertificateType certificateType, Pageable pageable);
    
    // Find by owner and status - using many-to-many relationship
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner AND c.status = :status")
    List<Certificate> findByOwnerAndStatus(@Param("owner") User owner, @Param("status") CertificateStatus status);
    
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner AND c.status = :status")
    Page<Certificate> findByOwnerAndStatus(@Param("owner") User owner, @Param("status") CertificateStatus status, Pageable pageable);
    
    // Find by owner and type - using many-to-many relationship
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner AND c.certificateType = :certificateType")
    List<Certificate> findByOwnerAndCertificateType(@Param("owner") User owner, @Param("certificateType") CertificateType certificateType);
    
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner AND c.certificateType = :certificateType")
    Page<Certificate> findByOwnerAndCertificateType(@Param("owner") User owner, @Param("certificateType") CertificateType certificateType, Pageable pageable);
    
    // Find by issuer certificate (for building chains)
    List<Certificate> findByIssuerCertificate(Certificate issuerCertificate);
    
    // Find CA certificates (Root and Intermediate)
    @Query("SELECT c FROM Certificate c WHERE c.certificateType IN ('ROOT', 'INTERMEDIATE')")
    List<Certificate> findCACertificates();
    
    // Find CA certificates by owner - using many-to-many relationship
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner AND c.certificateType IN ('ROOT', 'INTERMEDIATE')")
    List<Certificate> findCACertificatesByOwner(@Param("owner") User owner);
    
    // Find certificates in a chain (from a specific CA down to end-entities)
    @Query("SELECT c FROM Certificate c WHERE c.issuerCertificate = :ca OR c.issuerCertificate IN " +
           "(SELECT c2 FROM Certificate c2 WHERE c2.issuerCertificate = :ca)")
    List<Certificate> findCertificatesInChain(@Param("ca") Certificate ca);
    
    
    // Check if certificate exists by serial number
    boolean existsBySerialNumber(String serialNumber);
    
    // Find revoked certificates for CRL generation
    @Query("SELECT c FROM Certificate c WHERE c.status = 'REVOKED' AND c.issuerCertificate = :issuer")
    List<Certificate> findRevokedCertificatesByIssuer(@Param("issuer") Certificate issuer);
    
    // Find certificates by owner or issued by owner's CA certificates - using many-to-many relationship
    @Query("SELECT c FROM User u JOIN u.myCertificates c WHERE u = :owner OR " +
           "(c.issuerCertificate IS NOT NULL AND c.issuerCertificate IN (SELECT c2 FROM User u2 JOIN u2.myCertificates c2 WHERE u2 = :issuerOwner))")
    Page<Certificate> findByOwnerOrIssuerCertificateOwner(@Param("owner") User owner, 
                                                         @Param("issuerOwner") User issuerOwner, 
                                                         Pageable pageable);
}
