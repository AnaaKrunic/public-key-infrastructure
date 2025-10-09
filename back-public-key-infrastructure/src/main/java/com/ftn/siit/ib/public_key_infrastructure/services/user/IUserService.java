package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;

public interface IUserService {
    void register(UserRegistrationDTO dto);
    boolean activateAccount(String token);
    String login(LoginDTO dto);
    void enableMfa(String email, String secret);
    boolean verifyMfaCode(String email, String code);
}
