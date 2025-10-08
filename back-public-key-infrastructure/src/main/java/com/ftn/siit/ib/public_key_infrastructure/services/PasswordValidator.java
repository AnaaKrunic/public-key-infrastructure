package com.ftn.siit.ib.public_key_infrastructure.services;

public class PasswordValidator {
    private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";

    public static boolean isValid(String password) {
        return password != null && password.matches(PASSWORD_PATTERN);
    }
}
