package com.ftn.siit.ib.public_key_infrastructure.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/crl")
@CrossOrigin(origins = "*")
public class CRLController {

    // ===== CRL Access (Public) =====
    
    @GetMapping("/{caSerialNumber}")
    public ResponseEntity<?> getCRL(@PathVariable String caSerialNumber) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CRL retrieval not implemented yet");
    }
    
    @GetMapping("/{caSerialNumber}/info")
    public ResponseEntity<?> getCRLInfo(@PathVariable String caSerialNumber) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CRL info retrieval not implemented yet");
    }
    
    // ===== CRL Management (Admin/CA User) =====
    
    @PostMapping("/{caSerialNumber}/regenerate")
    public ResponseEntity<?> regenerateCRL(@PathVariable String caSerialNumber) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CRL regeneration not implemented yet");
    }
    
    @GetMapping("/{caSerialNumber}/status")
    public ResponseEntity<?> getCRLStatus(@PathVariable String caSerialNumber) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CRL status retrieval not implemented yet");
    }
}
