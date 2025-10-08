package com.ftn.siit.ib.public_key_infrastructure.services;

import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class MFAService {
    private final DefaultSecretGenerator generator = new DefaultSecretGenerator();
    private final DefaultCodeVerifier verifier = new DefaultCodeVerifier(
            new DefaultCodeGenerator(HashingAlgorithm.SHA1),
            new SystemTimeProvider()
    );

    public String generateSecretKey() {
        return generator.generate();
    }

    public boolean verifyCode(String secret, String code) {
        return verifier.isValidCode(secret, code);
    }

    public String generateQrImage(String email, String secret) {
        try {
            QrData data = new QrData.Builder()
                    .label(email)
                    .secret(secret)
                    .issuer("PKISystem")
                    .build();

            ZxingPngQrGenerator qrGenerator = new ZxingPngQrGenerator();
            byte[] imageData = qrGenerator.generate(data);
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(imageData);
        } catch (Exception e) {
            throw new RuntimeException("Error with generating QR code.");
        }
    }
}
