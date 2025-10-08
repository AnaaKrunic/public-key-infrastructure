package com.ftn.siit.ib.public_key_infrastructure.controllers;

import com.ftn.siit.ib.public_key_infrastructure.services.MFAService;
import com.ftn.siit.ib.public_key_infrastructure.services.user.IUserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/mfa")
@CrossOrigin(origins = "*")
public class MFAController {

    private final MFAService mfaService;
    private final IUserService userService;

    public MFAController(MFAService mfaService, IUserService userService) {
        this.mfaService = mfaService;
        this.userService = userService;
    }
/*
    @PostMapping("/enable")
    public ResponseEntity<?> enableMfa(@RequestParam String email) {
        String secret = mfaService.generateSecretKey();
        userService.enableMfa(email, secret);

        String qrImage = mfaService.generateQrImage(email, secret);
        return ResponseEntity.ok(qrImage); // front može prikazati kao <img src="{{qrImage}}">
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyMfa(@RequestParam String email, @RequestParam String code) {
        boolean valid = userService.verifyMfaCode(email, code);
        if (valid) {
            return ResponseEntity.ok("MFA verified successfully!");
        } else {
            return ResponseEntity.badRequest().body("Invalid MFA code.");
        }
    }
 */
}