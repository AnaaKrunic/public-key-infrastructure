package com.ftn.siit.ib.public_key_infrastructure.services.user;

import com.ftn.siit.ib.public_key_infrastructure.dtos.LoginDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserRegistrationDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.UserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.CreateCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.dtos.ValidCAUserDTO;
import com.ftn.siit.ib.public_key_infrastructure.entities.Organization;
import com.ftn.siit.ib.public_key_infrastructure.entities.User;
import com.ftn.siit.ib.public_key_infrastructure.entities.Role;
import com.ftn.siit.ib.public_key_infrastructure.repositories.OrganizationRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.UserRepository;
import com.ftn.siit.ib.public_key_infrastructure.repositories.CertificateRepository;
import com.ftn.siit.ib.public_key_infrastructure.security.JwtUtil;
import com.ftn.siit.ib.public_key_infrastructure.services.EmailService;
import com.ftn.siit.ib.public_key_infrastructure.services.MFAService;
import com.ftn.siit.ib.public_key_infrastructure.services.PasswordValidator;
import com.ftn.siit.ib.public_key_infrastructure.services.CertificateService;
import com.ftn.siit.ib.public_key_infrastructure.entities.Certificate;
import com.ftn.siit.ib.public_key_infrastructure.entities.CertificateStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final CertificateRepository certificateRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final MFAService mfaService;
    private final JwtUtil jwtUtil;
    private final CertificateService certificateService;

    public UserService(UserRepository userRepository,
                       OrganizationRepository organizationRepository,
                       CertificateRepository certificateRepository,
                       PasswordEncoder passwordEncoder,
                       EmailService emailService,
                       MFAService mfaService,
                       JwtUtil jwtUtil,
                       CertificateService certificateService) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.certificateRepository = certificateRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.mfaService = mfaService;
        this.jwtUtil = jwtUtil;
        this.certificateService = certificateService;
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

        user.setEmailConfirmed(false);
        user.setRefreshToken(null);
        user.setRefreshTokenExpiresAt(null);

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
    public String login(LoginDTO dto) {
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
        
        if (user.getOrganization() != null) {
            UserDTO.OrganizationDTO orgDTO = new UserDTO.OrganizationDTO();
            orgDTO.setId(user.getOrganization().getId());
            orgDTO.setName(user.getOrganization().getName());
            userDTO.setOrganization(orgDTO);
        }
        
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

        // Filter CA users who have at least one active certificate using MyCertificates collection
        return caUsers.stream()
                .filter(user -> user.getMyCertificates().stream()
                        .anyMatch(cert -> certificateService.getStatus(cert) == CertificateStatus.ACTIVE))
                .map(user -> {
                    List<Certificate> activeCertificates = user.getMyCertificates().stream()
                            .filter(cert -> certificateService.getStatus(cert) == CertificateStatus.ACTIVE)
                            .collect(Collectors.toList());

                    ValidCAUserDTO dto = new ValidCAUserDTO();
                    dto.setId(user.getId());
                    dto.setEmail(user.getEmail());
                    dto.setFirstName(user.getFirstName());
                    dto.setLastName(user.getLastName());
                    dto.setOrganization(user.getOrganization() != null ? user.getOrganization().getName() : null);

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
        
        if (user.getOrganization() != null) {
            UserDTO.OrganizationDTO orgDTO = new UserDTO.OrganizationDTO();
            orgDTO.setId(user.getOrganization().getId());
            orgDTO.setName(user.getOrganization().getName());
            userDTO.setOrganization(orgDTO);
        }
        
        return userDTO;
    }

    @Override
    public UserDTO createCaUser(CreateCAUserDTO dto) {
        // Check if email already exists
        if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email is already in use.");
        }

        // Validate password
        if (!PasswordValidator.isValid(dto.getPassword())) {
            throw new IllegalArgumentException("Password doesn't meet the requirements.");
        }

        // Find or create organization
        Organization organization = organizationRepository.findByName(dto.getOrganization())
            .orElseGet(() -> {
                Organization newOrg = new Organization();
                newOrg.setName(dto.getOrganization());
                return organizationRepository.save(newOrg);
            });

        // Create CA user
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPasswordHash(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setRole(Role.CA_USER); // Set as CA_USER
        user.setOrganization(organization);
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

}
