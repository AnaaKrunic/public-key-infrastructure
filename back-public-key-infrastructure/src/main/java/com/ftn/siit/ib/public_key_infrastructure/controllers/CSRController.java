package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/csr")
@CrossOrigin(origins = "*")
public class CSRController {

    // ===== CSR Creation =====
    
    @PostMapping("/create")
    @PreAuthorize("hasRole('REGULAR_USER')")
    public ResponseEntity<?> createCSR(@RequestBody CreateCSRDTO dto) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CSR creation not implemented yet");
    }
    
    @PostMapping("/upload")
    @PreAuthorize("hasRole('REGULAR_USER')")
    public ResponseEntity<?> uploadCSR(
            @RequestParam("csrFile") MultipartFile csrFile,
            @RequestParam("selectedCAId") Long selectedCAId,
            @RequestParam(value = "templateId", required = false) Long templateId) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CSR upload not implemented yet");
    }
    
    // ===== CSR Query Operations =====
    
    @GetMapping("/my-requests")
    @PreAuthorize("hasRole('REGULAR_USER')")
    public ResponseEntity<?> listMyCSRs() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("My CSRs listing not implemented yet");
    }
    
    @GetMapping("/pending")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<?> listPendingCSRs() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Pending CSRs listing not implemented yet");
    }
    
    // ===== CSR Processing =====
    
    @PostMapping("/{id}/approve")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN')")
    public ResponseEntity<?> approveCSR(
            @PathVariable Long id,
            @RequestBody ApproveCSRDTO dto) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CSR approval not implemented yet");
    }
    
    @PostMapping("/{id}/reject")
    @PreAuthorize("hasAnyRole('CA_USER', 'ADMIN')")
    public ResponseEntity<?> rejectCSR(
            @PathVariable Long id,
            @RequestBody RejectCSRDTO dto) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CSR rejection not implemented yet");
    }
}
