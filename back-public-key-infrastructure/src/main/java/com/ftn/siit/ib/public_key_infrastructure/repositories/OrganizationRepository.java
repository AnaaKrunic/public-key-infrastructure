package com.ftn.siit.ib.public_key_infrastructure.repositories;

import com.ftn.siit.ib.public_key_infrastructure.entities.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {
    Optional<Organization> findByName(String name);
}
