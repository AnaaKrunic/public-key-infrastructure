package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.ValidCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import java.util.List;

public interface IUserService {
    void register(UserRegistrationDTO dto);
    boolean activateAccount(String token);
    String login(LoginDTO dto);
    void enableMfa(String email, String secret);
    boolean verifyMfaCode(String email, String code);
    User findByEmail(String email);
    UserDTO getCurrentUser(String email);
    List<UserDTO> getAllCaUsers();
    List<ValidCAUserDTO> getValidCaUsers();
    UserDTO createCaUser(CreateCAUserDTO dto);
}
