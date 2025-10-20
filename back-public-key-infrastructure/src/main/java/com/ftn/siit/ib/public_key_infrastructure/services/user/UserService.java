package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.RefreshTokenDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.TokenResponseDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.ValidCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
// import com.ftn.siit.ib.public_key_infrastructure.entities.UserRole; // unused
// import com.ftn.siit.ib.public_key_infrastructure.repositories.OrganizationRepository; // unused
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.security.JwtUtil;
import com.ftn.siit.ib.public_key_infrastructure.services.EmailService;
import com.ftn.siit.ib.public_key_infrastructure.services.MFAService;
import com.ftn.siit.ib.public_key_infrastructure.services.PasswordBreachService;
// import com.ftn.siit.ib.public_key_infrastructure.services.PasswordValidator; // unused duplicate
import com.ftn.siit.ib.public_key_infrastructure.services.CertificateService;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import com.ftn.siit.ib.public_key_infrastructure.services.PasswordValidator;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final MFAService mfaService;
    private final JwtUtil jwtUtil;
    private final CertificateService certificateService;
    private final PasswordValidator passwordValidator;
    private final PasswordBreachService passwordBreachService;

    public UserService(UserRepository userRepository,
                       CertificateRepository certificateRepository,
                       PasswordEncoder passwordEncoder,
                       EmailService emailService,
                       MFAService mfaService,
                       JwtUtil jwtUtil,
                       CertificateService certificateService,
                       PasswordValidator passwordValidator,
                       PasswordBreachService passwordBreachService) {
        this.userRepository = userRepository;
        this.certificateRepository = certificateRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.mfaService = mfaService;
        this.jwtUtil = jwtUtil;
        this.certificateService = certificateService;
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

        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPasswordHash(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setOrganization(dto.getOrganization());

        user.setEmailConfirmed(false);
        user.setRefreshToken(null);
        user.setRefreshTokenExpiresAt(null);
        //user.setOrganization(organization);
        user.setRole(Role.EE_USER);

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
        user.setEmailConfirmed(true);
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

        if (!user.isEmailConfirmed()) {
            throw new RuntimeException("Email not confirmed. Check your email.");
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
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Override
    public UserDTO getCurrentUser(String email) {
        User user = findByEmail(email);
        
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setEmail(user.getEmail());
        userDTO.setFirstName(user.getFirstName());
        userDTO.setLastName(user.getLastName());
        userDTO.setRole(user.getRole());
        userDTO.setEnabled(user.isEnabled());
        userDTO.setEmailConfirmed(user.isEmailConfirmed());
        userDTO.setMfaEnabled(user.isMfaEnabled());
        
        userDTO.setOrganization(user.getOrganization());
        
        return userDTO;
    }

    @Override
    public List<UserDTO> getAllCaUsers() {
        List<User> caUsers = userRepository.findByRole(Role.CA_USER);

        return caUsers.stream()
                .map(this::convertToUserDTO)
                .toList();
    }

    @Override
    public List<ValidCAUserDTO> getValidCaUsers() {
        // Get all CA users
        List<User> caUsers = userRepository.findByRole(Role.CA_USER);

        // Return all CA users, with validity dates calculated for those with certificates
        return caUsers.stream()
                .map(user -> {
                    List<Certificate> activeCertificates = user.getMyCertificates().stream()
                            .filter(cert -> certificateService.getStatus(cert) == CertificateStatus.ACTIVE)
                            .collect(Collectors.toList());

                    ValidCAUserDTO dto = new ValidCAUserDTO();
                    dto.setId(user.getId());
                    dto.setEmail(user.getEmail());
                    dto.setFirstName(user.getFirstName());
                    dto.setLastName(user.getLastName());
                    dto.setOrganization(user.getOrganization());

                    // Find min valid from and max valid until from active certificates
                    if (!activeCertificates.isEmpty()) {
                        dto.setMinValidFrom(activeCertificates.stream()
                                .map(Certificate::getValidFrom)
                                .min(LocalDateTime::compareTo)
                                .orElse(null));
                        dto.setMaxValidUntil(activeCertificates.stream()
                                .map(Certificate::getValidTo)
                                .max(LocalDateTime::compareTo)
                                .orElse(null));
                    }
                    // If no active certificates, minValidFrom and maxValidUntil will remain null

                    return dto;
                })
                .collect(Collectors.toList());
    }
    
    private UserDTO convertToUserDTO(User user) {
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setEmail(user.getEmail());
        userDTO.setFirstName(user.getFirstName());
        userDTO.setLastName(user.getLastName());
        userDTO.setRole(user.getRole());
        userDTO.setEnabled(user.isEnabled());
        userDTO.setEmailConfirmed(user.isEmailConfirmed());
        userDTO.setMfaEnabled(user.isMfaEnabled());
        
        userDTO.setOrganization(user.getOrganization());
        
        return userDTO;
    }

    @Override
    @Transactional
    public UserDTO createCaUser(CreateCAUserDTO dto) {
        // Check if email already exists
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already in use.");
        }


        if (passwordValidator.isValid(dto.getPassword())) {
            throw new IllegalArgumentException("Password doesn't meet the requirements.");
        }

        // Use organization name directly as string
        String organizationName = dto.getOrganization().trim();
        System.out.println("DEBUG: Using organization name: '" + organizationName + "'");

        // Create CA user
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPasswordHash(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setRole(Role.CA_USER); // Set as CA_USER
        user.setOrganization(organizationName); // Set organization as string
        user.setEnabled(true); // CA users are enabled by default
        user.setEmailConfirmed(true); // CA users are email confirmed by default
        user.setMfaEnabled(false); // MFA can be enabled later
        
        // Set activation token fields to null since CA users don't need activation
        user.setActivationToken(null);
        user.setTokenExpiration(null);
        user.setRefreshToken(null);
        user.setRefreshTokenExpiresAt(null);

        // Save user
        User savedUser = userRepository.save(user);
        
        // Add initial signing certificate to CA user using the new relationship model
        Certificate initialCert = certificateRepository.findById(dto.getInitialSigningCertificateId())
                .orElseThrow(() -> new RuntimeException("Initial signing certificate not found!"));
        savedUser.getMyCertificates().add(initialCert);
        userRepository.save(savedUser);
        
        // Convert to DTO and return
        return convertToUserDTO(savedUser);
    }

    public TokenResponseDTO refreshToken(RefreshTokenDTO dto) {
        if (!jwtUtil.validateToken(dto.getRefreshToken()) || !jwtUtil.isRefreshToken(dto.getRefreshToken())) {
            throw new RuntimeException("Invalid refresh token");
        }

        String email = jwtUtil.extractEmail(dto.getRefreshToken());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!dto.getRefreshToken().equals(user.getRefreshToken())) {
            // Refresh Token Automatic Reuse Detection: invalidate current token family
            user.setRefreshToken(null);
            user.setRefreshTokenExpiration(null);
            userRepository.save(user);
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
    public void assignRole(String email, Role role) {
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
