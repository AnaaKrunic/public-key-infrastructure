package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {
    
    // Find templates by CA issuer serial number
    List<CertificateTemplate> findByCaIssuerSerialNumber(String caIssuerSerialNumber);
    
    // Find template by name and CA issuer serial number
    Optional<CertificateTemplate> findByNameAndCaIssuerSerialNumber(String name, String caIssuerSerialNumber);
    
    // Check if template name exists for a CA issuer serial number
    boolean existsByNameAndCaIssuerSerialNumber(String name, String caIssuerSerialNumber);
}
