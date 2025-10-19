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
            String token = userService.login(loginDTO);
            return ResponseEntity.ok().body(Map.of("accessToken", token));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }
}