package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/templates")
@CrossOrigin(origins = "*")
public class TemplateController {

    // ===== Template Management =====
    
    @PostMapping
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> createTemplate(@RequestBody CreateTemplateDTO dto) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Template creation not implemented yet");
    }
    
    @GetMapping
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> listTemplates() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Template listing not implemented yet");
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> getTemplate(@PathVariable Long id) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Template retrieval not implemented yet");
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> updateTemplate(
            @PathVariable Long id,
            @RequestBody CreateTemplateDTO dto) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Template update not implemented yet");
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN')")
    public ResponseEntity<?> deleteTemplate(@PathVariable Long id) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Template deletion not implemented yet");
    }
}
