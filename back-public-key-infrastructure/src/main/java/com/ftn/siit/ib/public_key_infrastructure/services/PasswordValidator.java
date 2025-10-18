package com.ftn.siit.ib.public_key_infrastructure.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PasswordValidator {
    private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!\"#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_`{|}~])[\\x20-\\x7E]{8,64}$";
    
    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 64;
    
    private final PasswordBreachService passwordBreachService;

    @Autowired
    public PasswordValidator(PasswordBreachService passwordBreachService) {
        this.passwordBreachService = passwordBreachService;
    }

    public boolean isValid(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }
        
        if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            return false;
        }
        
        if (!password.matches(PASSWORD_PATTERN)) {
            return false;
        }
        
        return passwordBreachService.isPasswordSafe(password);
    }

    public static boolean isValidPattern(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }
        
        if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            return false;
        }
        
        return password.matches(PASSWORD_PATTERN);
    }
    
    public static String getPasswordRequirements() {
        return String.format(
            "Lozinka mora imati između %d i %d karaktera i sadržavati najmanje jedno malo slovo, jedno veliko slovo, jedan broj i jedan specijalni karakter.",
            MIN_LENGTH, MAX_LENGTH
        );
    }
}
