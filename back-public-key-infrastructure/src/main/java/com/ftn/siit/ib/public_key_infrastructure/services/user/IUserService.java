package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.RefreshTokenDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.TokenResponseDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.ValidCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import java.util.List;
import com.ftn.siit.ib.public_key_infrastructure.entities.UserRole;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;

public interface IUserService {
    void register(UserRegistrationDTO dto);
    boolean activateAccount(String token);
    TokenResponseDTO login(LoginDTO dto);
    TokenResponseDTO refreshToken(RefreshTokenDTO dto);
    void logout(String email);
    void assignRole(String email, Role role);
    boolean isPasswordSafe(String password);
    int getPasswordBreachCount(String password);
    void enableMfa(String email, String secret);
    boolean verifyMfaCode(String email, String code);
    boolean isMfaEnabled(String email);
    User findByEmail(String email);
    UserDTO getCurrentUser(String email);
    List<UserDTO> getAllCaUsers();
    List<ValidCAUserDTO> getValidCaUsers();
    UserDTO createCaUser(CreateCAUserDTO dto);
}
