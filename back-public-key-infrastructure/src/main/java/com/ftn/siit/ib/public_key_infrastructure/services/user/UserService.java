package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.Organization;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.repositories.OrganizationRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.security.JwtUtil;
import com.ftn.siit.ib.public_key_infrastructure.services.EmailService;
import com.ftn.siit.ib.public_key_infrastructure.services.MFAService;
import com.ftn.siit.ib.public_key_infrastructure.services.PasswordValidator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final MFAService mfaService;
    private final JwtUtil jwtUtil;

    public UserService(UserRepository userRepository,
                       OrganizationRepository organizationRepository,
                       PasswordEncoder passwordEncoder,
                       EmailService emailService,
                       MFAService mfaService,
                       JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.mfaService = mfaService;
        this.jwtUtil = jwtUtil;
    }


    @Override
    public void register(UserRegistrationDTO dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already in use.");
        }

        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords don't match.");
        }

        if (!PasswordValidator.isValid(dto.getPassword())) {
            throw new IllegalArgumentException("Password doesn't meet the requirements.");
        }

        Organization organization = organizationRepository.findByName(dto.getOrganization())
            .orElseGet(() -> {
                Organization newOrg = new Organization();
                newOrg.setName(dto.getOrganization());
                return organizationRepository.save(newOrg);
            });

        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPasswordHash(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setOrganization(organization);

        String token = UUID.randomUUID().toString();
        user.setActivationToken(token);
        user.setTokenExpiration(LocalDateTime.now().plusHours(24));
        user.setEnabled(false);

        userRepository.save(user);
        emailService.sendActivationEmail(user.getEmail(), token);
    }

    @Override
    public boolean activateAccount(String token) {
        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid activation token."));
        if (user.getTokenExpiration().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Token is expired.");
        }

        user.setEnabled(true);
        user.setActivationToken(null);
        user.setTokenExpiration(null);

        userRepository.save(user);
        return true;
    }

    @Override
    public String login(LoginDTO dto) {
        User user = userRepository.findByEmail(dto.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found."));

        if (!user.isEnabled()) {
            throw new RuntimeException("Account not activated. Check your email.");
        }

        if (!passwordEncoder.matches(dto.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials.");
        }

        if (user.isMfaEnabled()) {
            if (dto.getMfaCode() == null || !mfaService.verifyCode(user.getMfaSecret(), dto.getMfaCode())) {
                throw new RuntimeException("Invalid MFA code.");
            }
        }

        return jwtUtil.generateToken(user.getEmail());
    }


    @Override
    public void enableMfa(String email, String secret) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setMfaSecret(secret);
        user.setMfaEnabled(true);
        userRepository.save(user);
    }

    @Override
    public boolean verifyMfaCode(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.isMfaEnabled()) return false;
        return mfaService.verifyCode(user.getMfaSecret(), code);
    }

    @Override
    public boolean isMfaEnabled(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.isMfaEnabled();
    }

}
