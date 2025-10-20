package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.services.TemplateService;
import com.ftn.siit.ib.public_key_infrastructure.services.user.UserService;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/templates")
@CrossOrigin(origins = "*")
public class TemplateController {

    @Autowired
    private TemplateService templateService;

    @Autowired
    private UserService userService;

    // ===== Template Management =====
    
    @PostMapping("/create")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN')")
    public ResponseEntity<?> createTemplate(@RequestBody CreateTemplateDTO dto, Authentication authentication) {
        try {
            // Principal is typically username/email (String) or UserDetails; resolve our User entity by email
            String email = authentication.getName();
            User user = userService.findByEmail(email);
            TemplateDTO template = templateService.createTemplate(dto, user);
            return ResponseEntity.ok(template);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @GetMapping("/all")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN', 'EE_USER')")
    public ResponseEntity<?> getAllTemplates() {
        try {
            List<TemplateDTO> templates = templateService.getAllTemplates();
            return ResponseEntity.ok(templates);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @GetMapping("/ca/{caSerialNumber}")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN', 'EE_USER')")
    public ResponseEntity<?> getTemplatesForCA(@PathVariable String caSerialNumber) {
        try {
            List<TemplateDTO> templates = templateService.getTemplatesForCA(caSerialNumber);
            return ResponseEntity.ok(templates);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN', 'EE_USER')")
    public ResponseEntity<?> getTemplate(@PathVariable Long id) {
        try {
            TemplateDTO template = templateService.getTemplateById(id);
            return ResponseEntity.ok(template);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN')")
    public ResponseEntity<?> updateTemplate(
            @PathVariable Long id,
            @RequestBody UpdateTemplateDTO dto,
            Authentication authentication) {
        try {
            String email = authentication.getName();
            User user = userService.findByEmail(email);
            TemplateDTO template = templateService.updateTemplate(id, dto, user);
            return ResponseEntity.ok(template);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN')")
    public ResponseEntity<?> deleteTemplate(@PathVariable Long id, Authentication authentication) {
        try {
            String email = authentication.getName();
            User user = userService.findByEmail(email);
            templateService.deleteTemplate(id, user);
            return ResponseEntity.ok(Map.of("message", "Template deleted successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    // ===== Template Validation =====
    
    @PostMapping("/validate-cn")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN', 'EE_USER')")
    public ResponseEntity<?> validateCN(@RequestBody Map<String, String> request) {
        try {
            String cn = request.get("cn");
            String regex = request.get("regex");
            
            if (cn == null || regex == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "CN and regex are required"));
            }
            
            boolean isValid = templateService.validateCN(cn, regex);
            return ResponseEntity.ok(Map.of("isValid", isValid));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/validate-san")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN', 'EE_USER')")
    public ResponseEntity<?> validateSAN(@RequestBody Map<String, String> request) {
        try {
            String san = request.get("san");
            String regex = request.get("regex");
            
            if (san == null || regex == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "SAN and regex are required"));
            }
            
            boolean isValid = templateService.validateSAN(san, regex);
            return ResponseEntity.ok(Map.of("isValid", isValid));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
