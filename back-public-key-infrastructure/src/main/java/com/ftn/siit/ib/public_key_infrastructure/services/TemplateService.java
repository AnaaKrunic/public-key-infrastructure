package com.ftn.siit.ib.public_key_infrastructure.services;

import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateTemplateDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.TemplateDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UpdateTemplateDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateTemplate;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateTemplateRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.access.AccessDeniedException;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/**
 * TemplateService manages certificate templates for CA users.
 * 
 * Certificate templates define reusable constraints and defaults for
 * certificate issuance, including:
 * - Common Name patterns (regex)
 * - Subject Alternative Name patterns (regex)
 * - Maximum validity period (TTL)
 * - Default key usage and extended key usage
 * - Issuer CA certificate
 * 
 * Templates simplify certificate issuance by enforcing consistent
 * policies and reducing configuration errors.
 */
@Service
@Transactional
public class TemplateService {

    private final CertificateTemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;

    public TemplateService(
            CertificateTemplateRepository templateRepository,
            CertificateRepository certificateRepository) {
        this.templateRepository = templateRepository;
        this.certificateRepository = certificateRepository;
    }

    /**
     * Creates a new certificate template.
     */
    public TemplateDTO createTemplate(CreateTemplateDTO dto, User caUser) {
        // Validate user has permission (support enum Role or string)
        Object roleObj = caUser.getRole();
        String roleName = roleObj == null ? null : roleObj.toString();
        if (roleName == null || !("CA_USER".equals(roleName) || "ADMIN".equals(roleName))) {
            throw new AccessDeniedException("Only CA_USER and ADMIN can create templates");
        }
        
        // Validate CA issuer certificate exists
        if (!certificateRepository.existsBySerialNumber(dto.getCaIssuerSerialNumber())) {
            throw new IllegalArgumentException("CA issuer certificate not found: " + dto.getCaIssuerSerialNumber());
        }
        
        // Validate regex patterns
        validateRegexPattern(dto.getCnRegex(), "CN regex");
        validateRegexPattern(dto.getSanRegex(), "SAN regex");
        
        // Create template entity
        CertificateTemplate template = new CertificateTemplate();
        template.setName(dto.getName());
        template.setCaIssuerSerialNumber(dto.getCaIssuerSerialNumber());
        template.setCnRegex(dto.getCnRegex());
        template.setSanRegex(dto.getSanRegex());
        template.setTtl(dto.getTtl());
        template.setKeyUsage(dto.getKeyUsage());
        template.setExtendedKeyUsage(dto.getExtendedKeyUsage());
        template.setCreatedBy(caUser);
        
        // Save template
        CertificateTemplate savedTemplate = templateRepository.save(template);
        
        return convertToDTO(savedTemplate);
    }

    /**
     * Updates an existing certificate template.
     */
    public TemplateDTO updateTemplate(Long templateId, UpdateTemplateDTO dto, User caUser) {
        CertificateTemplate template = templateRepository.findById(templateId)
            .orElseThrow(() -> new IllegalArgumentException("Template not found: " + templateId));
        
        // Check permissions
        if (!hasModifyPermission(template, caUser)) {
            throw new AccessDeniedException("You don't have permission to modify this template");
        }
        
        // Validate regex patterns
        validateRegexPattern(dto.getCnRegex(), "CN regex");
        validateRegexPattern(dto.getSanRegex(), "SAN regex");
        
        // Update fields
        template.setName(dto.getName());
        template.setCnRegex(dto.getCnRegex());
        template.setSanRegex(dto.getSanRegex());
        template.setTtl(dto.getTtl());
        template.setKeyUsage(dto.getKeyUsage());
        template.setExtendedKeyUsage(dto.getExtendedKeyUsage());
        
        // Save updated template
        CertificateTemplate savedTemplate = templateRepository.save(template);
        
        return convertToDTO(savedTemplate);
    }

    /**
     * Deletes a certificate template.
     */
    public void deleteTemplate(Long templateId, User requester) {
        CertificateTemplate template = templateRepository.findById(templateId)
            .orElseThrow(() -> new IllegalArgumentException("Template not found: " + templateId));
        
        // Check permissions
        if (!hasModifyPermission(template, requester)) {
            throw new AccessDeniedException("You don't have permission to delete this template");
        }
        
        // Delete template
        templateRepository.delete(template);
    }

    /**
     * Lists all templates.
     */
    public List<TemplateDTO> getAllTemplates() {
        List<CertificateTemplate> templates = templateRepository.findAll();
        return templates.stream()
            .map(this::convertToDTO)
            .collect(Collectors.toList());
    }
    
    /**
     * Lists templates for a specific CA issuer.
     */
    public List<TemplateDTO> getTemplatesForCA(String caSerialNumber) {
        List<CertificateTemplate> templates = templateRepository.findByCaIssuerSerialNumber(caSerialNumber);
        return templates.stream()
            .map(this::convertToDTO)
            .collect(Collectors.toList());
    }
    
    /**
     * Gets a specific template by ID.
     */
    public TemplateDTO getTemplateById(Long templateId) {
        CertificateTemplate template = templateRepository.findById(templateId)
            .orElseThrow(() -> new IllegalArgumentException("Template not found: " + templateId));
        return convertToDTO(template);
    }
    
    /**
     * Validates CN against template regex.
     */
    public boolean validateCN(String cn, String regex) {
        try {
            Pattern pattern = Pattern.compile(regex);
            return pattern.matcher(cn).matches();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
    
    /**
     * Validates SAN against template regex.
     */
    public boolean validateSAN(String san, String regex) {
        try {
            Pattern pattern = Pattern.compile(regex);
            return pattern.matcher(san).matches();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    /**
     * Converts a CertificateTemplate entity to a TemplateDTO for API responses.
     */
    private TemplateDTO convertToDTO(CertificateTemplate template) {
        TemplateDTO dto = new TemplateDTO();
        dto.setId(template.getId());
        dto.setName(template.getName());
        dto.setCaIssuerSerialNumber(template.getCaIssuerSerialNumber());
        dto.setCnRegex(template.getCnRegex());
        dto.setSanRegex(template.getSanRegex());
        dto.setTtl(template.getTtl());
        dto.setKeyUsage(template.getKeyUsage());
        dto.setExtendedKeyUsage(template.getExtendedKeyUsage());
        dto.setCreatedAt(template.getCreatedAt());
        dto.setUpdatedAt(template.getUpdatedAt());
        
        // Set created by user info
        if (template.getCreatedBy() != null) {
            TemplateDTO.UserDTO userDTO = new TemplateDTO.UserDTO();
            userDTO.setId(template.getCreatedBy().getId());
            userDTO.setEmail(template.getCreatedBy().getEmail());
            userDTO.setFirstName(template.getCreatedBy().getFirstName());
            userDTO.setLastName(template.getCreatedBy().getLastName());
            dto.setCreatedBy(userDTO);
        }
        
        return dto;
    }

    /**
     * Checks if a user has permission to modify a template.
     */
    private boolean hasModifyPermission(CertificateTemplate template, User requester) {
        // ADMIN can modify any template
        if (requester.getRole().equals("ADMIN")) {
            return true;
        }
        
        // Template owner can modify their templates
        return template.getCreatedBy().getId().equals(requester.getId());
    }
    
    /**
     * Validates regex pattern syntax.
     */
    private void validateRegexPattern(String regex, String fieldName) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException("Invalid " + fieldName + " pattern: " + e.getMessage());
        }
    }
}

