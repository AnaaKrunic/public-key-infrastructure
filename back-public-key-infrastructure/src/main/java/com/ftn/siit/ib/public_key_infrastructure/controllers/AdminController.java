package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.AssignRoleDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.UserRole;
import com.ftn.siit.ib.public_key_infrastructure.services.user.IUserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "*")
public class AdminController {

    private final IUserService userService;

    public AdminController(IUserService userService) {
        this.userService = userService;
    }

    @PostMapping("/assign-role")
    public ResponseEntity<?> assignRole(@RequestBody AssignRoleDTO assignRoleDTO) {
        try {
            // Proverava da li je dozvoljena uloga za dodelu
            if (assignRoleDTO.getRole() == UserRole.ADMIN) {
                return ResponseEntity.badRequest().body(Map.of("message", "Cannot assign ADMIN role through API"));
            }

            userService.assignRole(assignRoleDTO.getEmail(), assignRoleDTO.getRole());
            return ResponseEntity.ok().body(Map.of("message", "Role assigned successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/assign-ca-role")
    public ResponseEntity<?> assignCARole(@RequestParam String email) {
        try {
            userService.assignRole(email, UserRole.CA_USER);
            return ResponseEntity.ok().body(Map.of("message", "CA role assigned successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}
