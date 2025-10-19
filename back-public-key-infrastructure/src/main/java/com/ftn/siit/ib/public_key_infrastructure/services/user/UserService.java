package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.RefreshTokenDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.TokenResponseDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.Organization;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.entities.UserRole;
import com.ftn.siit.ib.public_key_infrastructure.repositories.OrganizationRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.security.JwtUtil;
import com.ftn.siit.ib.public_key_infrastructure.services.EmailService;
import com.ftn.siit.ib.public_key_infrastructure.services.MFAService;
import com.ftn.siit.ib.public_key_infrastructure.services.PasswordBreachService;
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
    private final PasswordValidator passwordValidator;
    private final PasswordBreachService passwordBreachService;

    public UserService(UserRepository userRepository,
                       OrganizationRepository organizationRepository,
                       PasswordEncoder passwordEncoder,
                       EmailService emailService,
                       MFAService mfaService,
                       JwtUtil jwtUtil,
                       PasswordValidator passwordValidator,
                       PasswordBreachService passwordBreachService) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.mfaService = mfaService;
        this.jwtUtil = jwtUtil;
        this.passwordValidator = passwordValidator;
        this.passwordBreachService = passwordBreachService;
    }


    @Override
    public void register(UserRegistrationDTO dto) {
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already in use.");
        }

        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords don't match.");
        }

        if (!passwordValidator.isValid(dto.getPassword())) {
            throw new IllegalArgumentException("Password doesn't meet the requirements or has been compromised in data breaches.");
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
        user.setRole(UserRole.USER);

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
    public TokenResponseDTO login(LoginDTO dto) {
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

        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail());
        
        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiration(LocalDateTime.now().plusDays(7));
        userRepository.save(user);

        return new TokenResponseDTO(accessToken, refreshToken, 15 * 60); // 15 minutes in seconds
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

    @Override
    public TokenResponseDTO refreshToken(RefreshTokenDTO dto) {
        if (!jwtUtil.validateToken(dto.getRefreshToken()) || !jwtUtil.isRefreshToken(dto.getRefreshToken())) {
            throw new RuntimeException("Invalid refresh token");
        }

        String email = jwtUtil.extractEmail(dto.getRefreshToken());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!dto.getRefreshToken().equals(user.getRefreshToken())) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (user.getRefreshTokenExpiration() == null || user.getRefreshTokenExpiration().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        String newAccessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getRole().name());
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getEmail());

        user.setRefreshToken(newRefreshToken);
        user.setRefreshTokenExpiration(LocalDateTime.now().plusDays(7));
        userRepository.save(user);

        return new TokenResponseDTO(newAccessToken, newRefreshToken, 15 * 60); // 15 minutes in seconds
    }

    @Override
    public void logout(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setRefreshToken(null);
        user.setRefreshTokenExpiration(null);
        userRepository.save(user);
    }

    @Override
    public void assignRole(String email, UserRole role) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setRole(role);
        userRepository.save(user);
    }

    @Override
    public boolean isPasswordSafe(String password) {
        return passwordValidator.isValid(password);
    }

    @Override
    public int getPasswordBreachCount(String password) {
        return passwordBreachService.getBreachCount(password);
    }

}
