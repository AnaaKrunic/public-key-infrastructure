package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateCAUserDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "*")
public class AdminController {

    // ===== User Management =====
    
    @PostMapping("/users/ca")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createCAUser(@RequestBody CreateCAUserDTO dto) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("CA user creation not implemented yet");
    }
    
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> listUsers() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("User listing not implemented yet");
    }
    
    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("User retrieval not implemented yet");
    }
    
    @PutMapping("/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changeUserRole(
            @PathVariable Long id,
            @RequestParam String role) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("User role change not implemented yet");
    }
    
    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("User deletion not implemented yet");
    }
    
    // ===== System Management =====
    
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getSystemStatistics() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("System statistics not implemented yet");
    }
    
    @PostMapping("/maintenance/cleanup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> performMaintenanceCleanup() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                .body("Maintenance cleanup not implemented yet");
    }
}
