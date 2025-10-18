package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.RefreshTokenDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.TokenResponseDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.UserRole;

public interface IUserService {
    void register(UserRegistrationDTO dto);
    boolean activateAccount(String token);
    TokenResponseDTO login(LoginDTO dto);
    TokenResponseDTO refreshToken(RefreshTokenDTO dto);
    void logout(String email);
    void assignRole(String email, UserRole role);
    boolean isPasswordSafe(String password);
    int getPasswordBreachCount(String password);
    void enableMfa(String email, String secret);
    boolean verifyMfaCode(String email, String code);
    boolean isMfaEnabled(String email);
}
