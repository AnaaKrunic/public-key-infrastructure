package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateTemplate;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {
    
    // Find templates by CA issuer
    List<CertificateTemplate> findByCaIssuer(User caIssuer);
    
    // Find template by name and CA issuer
    Optional<CertificateTemplate> findByNameAndCaIssuer(String name, User caIssuer);
    
    // Find templates by issuer certificate
    List<CertificateTemplate> findByIssuerCertificateId(Long issuerCertificateId);
    
    // Check if template name exists for a CA issuer
    boolean existsByNameAndCaIssuer(String name, User caIssuer);
    
    // Find templates by CA issuer's organization
    @Query("SELECT t FROM CertificateTemplate t WHERE t.caIssuer.organization = :organizationName")
    List<CertificateTemplate> findByCaIssuerOrganization(@Param("organizationName") String organizationName);
}
