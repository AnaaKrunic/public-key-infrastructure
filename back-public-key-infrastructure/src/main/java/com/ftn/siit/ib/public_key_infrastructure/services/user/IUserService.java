package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;

public interface IUserService {
    void register(UserRegistrationDTO dto);
    boolean activateAccount(String token);
}
