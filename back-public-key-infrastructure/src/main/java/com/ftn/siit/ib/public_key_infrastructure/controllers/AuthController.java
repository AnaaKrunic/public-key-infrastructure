package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.dtos.*;
import com.ftn.siit.ib.public_key_infrastructure.services.user.IUserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final IUserService userService;

    public AuthController(IUserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDTO dto) {
        userService.register(dto);
        return ResponseEntity.ok().body(Map.of("message", "User registered successfully. Check your email for activation link."));
    }

    @GetMapping("/activate")
    public ResponseEntity<?> activateUser(@RequestParam("token") String token) {
        boolean activated = userService.activateAccount(token);

        if (activated) {
            return ResponseEntity.ok().body(Map.of("message", "Account activated successfully."));
        } else {
            return ResponseEntity.badRequest().body(Map.of("message", "Invalid or expired activation token."));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO loginDTO) {
        try {
            TokenResponseDTO tokenResponse = userService.login(loginDTO);
            return ResponseEntity.ok().body(tokenResponse);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenDTO refreshTokenDTO) {
        try {
            TokenResponseDTO tokenResponse = userService.refreshToken(refreshTokenDTO);
            return ResponseEntity.ok().body(tokenResponse);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String email) {
        try {
            userService.logout(email);
            return ResponseEntity.ok().body(Map.of("message", "Logged out successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/check-password-breach")
    public ResponseEntity<?> checkPasswordBreach(@RequestBody Map<String, String> request) {
        try {
            String password = request.get("password");
            if (password == null || password.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Password is required"));
            }
            
            boolean isSafe = userService.isPasswordSafe(password);
            int breachCount = userService.getPasswordBreachCount(password);
            
            return ResponseEntity.ok().body(Map.of(
                "isSafe", isSafe,
                "breachCount", breachCount,
                "message", isSafe ? "Password is safe" : "Password has been compromised"
            ));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}