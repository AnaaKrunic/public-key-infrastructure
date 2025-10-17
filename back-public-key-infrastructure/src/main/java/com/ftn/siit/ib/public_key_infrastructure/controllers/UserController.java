package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.services.user.IUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.data.domain.Pageable;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "*")
public class UserController {

    private final IUserService userService;

    public UserController(IUserService userService) {
        this.userService = userService;
    }

    /**
     * Lists every Certificate Authority (CA) user.
     * Requires authentication.
     */
    @GetMapping("/get-all-ca-users")
    public ResponseEntity<?> getAllCaUsers() {
        try {
            // Get current user from security context to verify authentication
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String currentUserEmail = authentication.getName();
            
            // Verify current user exists (authentication check)
            userService.findByEmail(currentUserEmail);
            
            // Get all CA users
            var caUsers = userService.getAllCaUsers();
            
            return ResponseEntity.ok(caUsers);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving CA users: " + e.getMessage());
        }
    }

    /**
     * Lists CA users whose signing certificates are still valid.
     * Requires authentication.
     */
    @GetMapping("/get-valid-ca-users")
    public ResponseEntity<?> getValidCaUsers() {
        try {
            // Get current user from security context to verify authentication
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String currentUserEmail = authentication.getName();

            // Verify current user exists (authentication check)
            userService.findByEmail(currentUserEmail);

            // Get valid CA users
            var validCaUsers = userService.getValidCaUsers();

            return ResponseEntity.ok(validCaUsers);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving valid CA users: " + e.getMessage());
        }
    }

    /**
     * Creates a new CA user and attaches the initial signing certificate.
     * Requires Admin role.
     */
    @PostMapping("/register-ca")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> registerCa(@RequestBody CreateCAUserDTO dto) {
        try {
            // Get current user from security context to verify admin role
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String currentUserEmail = authentication.getName();
            
            // Verify current user exists and is admin
            userService.findByEmail(currentUserEmail);
            
            // Create CA user
            UserDTO createdUser = userService.createCaUser(dto);
            
            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
            
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid request: " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error creating CA user: " + e.getMessage());
        }
    }

    /**
     * Returns the identity and roles of the authenticated caller.
     * Requires authentication.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getMe() {
        try {
            // Get current user from security context
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            
            // Get user information
            UserDTO userDTO = userService.getCurrentUser(email);
            
            return ResponseEntity.ok(userDTO);
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving user information: " + e.getMessage());
        }
    }
}
