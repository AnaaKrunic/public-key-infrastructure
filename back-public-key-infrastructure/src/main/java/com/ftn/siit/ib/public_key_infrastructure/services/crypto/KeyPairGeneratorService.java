package com.ftn.siit.ib.public_key_infrastructure.services.crypto;

import org.springframework.stereotype.Service;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Service
public class KeyPairGeneratorService {

    private static final String ALGORITHM = "RSA";
    private static final int[] VALID_KEY_SIZES = {2048, 4096};

    /**
     * Generates an RSA key pair with the specified key size.
     * 
     * @param keySize The key size in bits (must be 2048 or 4096)
     * @return A KeyPair containing the generated private and public keys
     * @throws IllegalArgumentException if keySize is not 2048 or 4096
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateKeyPair(int keySize) {
        validateKeySize(keySize);
        
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            keyPairGenerator.initialize(keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not available", e);
        }
    }

    /**
     * Validates that the key size is supported.
     * 
     * @param keySize The key size to validate
     * @throws IllegalArgumentException if keySize is not valid
     */
    private void validateKeySize(int keySize) {
        if (keySize <= 0) {
            throw new IllegalArgumentException("Key size must be a positive integer");
        }
        
        boolean isValid = false;
        for (int validSize : VALID_KEY_SIZES) {
            if (keySize == validSize) {
                isValid = true;
                break;
            }
        }
        
        if (!isValid) {
            throw new IllegalArgumentException("Key size must be 2048 or 4096 bits");
        }
    }
}
