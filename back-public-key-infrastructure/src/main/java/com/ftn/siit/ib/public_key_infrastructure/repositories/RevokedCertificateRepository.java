package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.RevokedCertificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, Long> {
    
    // Find by certificate
    Optional<RevokedCertificate> findByCertificate(Certificate certificate);
    
    // Find by certificate serial number
    Optional<RevokedCertificate> findByCertificateSerialNumber(String serialNumber);
    
    // Find all revoked certificates
    List<RevokedCertificate> findAll();
    
    // Find revoked certificates by issuer
    @Query("SELECT rc FROM RevokedCertificate rc WHERE rc.issuerCertificate = :issuer")
    List<RevokedCertificate> findByIssuerCertificate(@Param("issuer") Certificate issuer);
    
    // Check if certificate is already revoked
    boolean existsByCertificate(Certificate certificate);
    
    boolean existsByCertificateSerialNumber(String serialNumber);
}