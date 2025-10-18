package com.ftn.siit.ib.public_key_infrastructure.services;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service
public class PasswordBreachService {
    
    private static final String HIBP_API_URL = "https://api.pwnedpasswords.com/range/";
    private final RestTemplate restTemplate;

    public PasswordBreachService() {
        this.restTemplate = new RestTemplate();
    }

    /**
     * Proverava da li je lozinka kompromitovana u poznatim bazama podataka
     * Koristi HaveIBeenPwned API sa k-range metodom za sigurnost
     * 
     * @param password lozinka za proveru
     * @return broj puta koliko je lozinka pronađena u bazama
     */
    public int checkPasswordBreach(String password) {
        try {
            String sha1Hash = calculateSHA1(password);
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5).toUpperCase();

            String response = restTemplate.getForObject(HIBP_API_URL + prefix, String.class);
            
            if (response != null) {
                return parseResponseForSuffix(response, suffix);
            }
            
            return 0;
        } catch (Exception e) {
            System.err.println("Error checking password breach: " + e.getMessage());
            return 0;
        }
    }

    private String calculateSHA1(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    private int parseResponseForSuffix(String response, String suffix) {
        String[] lines = response.split("\r\n");
        for (String line : lines) {
            if (line.startsWith(suffix + ":")) {
                String countStr = line.substring(suffix.length() + 1);
                try {
                    return Integer.parseInt(countStr);
                } catch (NumberFormatException e) {
                    return 0;
                }
            }
        }
        return 0;
    }

    public boolean isPasswordSafe(String password) {
        int breachCount = checkPasswordBreach(password);
        return breachCount == 0;
    }

    public int getBreachCount(String password) {
        return checkPasswordBreach(password);
    }
}
