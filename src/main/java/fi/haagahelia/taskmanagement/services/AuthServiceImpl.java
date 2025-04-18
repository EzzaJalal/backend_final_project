package fi.haagahelia.taskmanagement.services;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import fi.haagahelia.taskmanagement.domain.User;
import fi.haagahelia.taskmanagement.domain.UserRepository;
import fi.haagahelia.taskmanagement.domain.UserRole;
import fi.haagahelia.taskmanagement.domain.dto.AuthenticationRequest;
import fi.haagahelia.taskmanagement.domain.dto.AuthenticationResponse;
import fi.haagahelia.taskmanagement.domain.dto.SignupRequest;
import fi.haagahelia.taskmanagement.domain.dto.UserDto;
import fi.haagahelia.taskmanagement.utils.EmailService;
import fi.haagahelia.taskmanagement.utils.JwtUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.thymeleaf.context.Context;

// Service implementation for user authentication-related actions.
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements authService {

    // Logger to track service activities for debugging and monitoring.
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository; // Repository for accessing user data.
    private final EmailService emailService; // Service for sending emails.
    private final AuthenticationManager authenticationManager; // Spring Security authentication manager.
    private final JwtUtil jwtUtil; // Utility for JWT token generation and validation.

    @Value("${app.base-url}")
    private String baseUrl; // Injected base URL from application.properties

    // Post-construct lifecycle method to create an admin account if one does not
    // already exist.
    @PostConstruct
    public void createAdminAccount() {
        try {
            Optional<User> optionalUser = userRepository.findByUserRole(UserRole.ADMIN);
            if (optionalUser.isEmpty()) {
                // Create and save admin user with default credentials.
                User user = new User();
                user.setEmail("admin@test.com");
                user.setName("admin");
                user.setPassword(new BCryptPasswordEncoder().encode("admin"));
                user.setUserRole(UserRole.ADMIN);
                user.setVerified(true);
                userRepository.saveAndFlush(user);
                logger.info("Admin account created successfully: {}", user.getEmail());
            } else {
                // Admin account exists, ensure it's verified.
                User admin = optionalUser.get();
                if (!admin.isVerified()) {
                    admin.setVerified(true);
                    userRepository.saveAndFlush(admin);
                    logger.info("Admin account verified: {}", admin.getEmail());
                } else {
                    logger.info("Admin account already exists and is verified: {}", admin.getEmail());
                }
            }
        } catch (Exception e) {
            // Log error if admin account creation or verification fails.
            logger.error("Failed to create or verify admin account: {}", e.getMessage(), e);
        }
    }

    @Override
    @Transactional
    public UserDto signupUser(SignupRequest signupRequest) {
        // Creating a new user from the signup request.
        User user = new User();
        user.setEmail(signupRequest.getEmail());
        user.setName(signupRequest.getName());
        user.setPassword(new BCryptPasswordEncoder().encode(signupRequest.getPassword()));
        user.setUserRole(UserRole.EMPLOYEE); // Default role for new users.
        user.setVerified(false); // User needs to verify email after signup.

        // Generating a unique verification token and expiry date for the email
        // verification.
        String verificationToken = UUID.randomUUID().toString();
        LocalDateTime expiryDate = LocalDateTime.now().plusHours(24);
        user.setVerificationToken(verificationToken);
        user.setVerificationTokenExpiryDate(expiryDate);
        logger.debug("Before saving user: verificationToken={}, expiryDate={}", verificationToken, expiryDate);

        // Save the user and ensure data is persisted by flushing to the database
        // immediately.
        User createdUser = userRepository.save(user);
        userRepository.flush(); // Ensure entity is written to the database.
        logger.debug("User saved: verificationToken={}, expiryDate={}", createdUser.getVerificationToken(),
                createdUser.getVerificationTokenExpiryDate());

        // Verify the token was saved by fetching the user again.
        Optional<User> savedUser = userRepository.findFirstByEmail(user.getEmail());
        if (savedUser.isPresent()) {
            logger.debug("Fetched user after save: verificationToken={}, expiryDate={}",
                    savedUser.get().getVerificationToken(), savedUser.get().getVerificationTokenExpiryDate());
        } else {
            logger.error("User not found after save: {}", user.getEmail());
            throw new RuntimeException("Failed to save user during signup");
        }

        // Sending the email verification link to the user using the injected base URL.
        String verificationLink = baseUrl + "/api/auth/verify-email?token=" + verificationToken;
        Context context = new Context();
        context.setVariable("verificationLink", verificationLink);
        context.setVariable("isSuccessPage", false); // For email body template.
        emailService.sendHtmlEmail(user.getEmail(), "Verify Your Email", "email-verification", context);
        logger.debug("Verification email sent to: {}", user.getEmail());

        // Return a DTO representation of the newly created user.
        return convertToUserDto(createdUser);
    }

    @Override
    public AuthenticationResponse login(AuthenticationRequest authenticationRequest) {
        // Authenticate the user using the provided email and password.
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()));
        User user = (User) authentication.getPrincipal();

        // Check if the user is verified before allowing login.
        if (!user.isEnabled()) {
            logger.warn("User {} is not verified. Cannot log in.", user.getEmail());
            throw new RuntimeException("User account is not verified. Please verify your email to log in.");
        }

        // Log successful authentication details and authorities for debugging purposes.
        logger.info("User {} successfully authenticated with role {}", user.getEmail(), user.getUserRole());
        logger.info("User authorities: {}", authentication.getAuthorities());

        // Generate and return a JWT token for the authenticated user.
        String jwt = jwtUtil.generateToken(user);
        logger.debug("Generated JWT token for user: {}", user.getEmail());

        AuthenticationResponse response = new AuthenticationResponse();
        response.setJwt(jwt);
        response.setUserId(user.getId());
        response.setUserRole(user.getUserRole());
        return response;
    }

    @Override
    public boolean hasUserWithEmail(String email) {
        // Check if a user exists with the provided email.
        return userRepository.findFirstByEmail(email).isPresent();
    }

    @Override
    @Transactional
    public void forgotPassword(String email) {
        Optional<User> optionalUser = userRepository.findFirstByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            // Generate a password reset token and set an expiry date for the token.
            String resetPasswordToken = UUID.randomUUID().toString();
            LocalDateTime expiryDate = LocalDateTime.now().plusHours(1);
            user.setResetPasswordToken(resetPasswordToken);
            user.setResetPasswordTokenExpiryDate(expiryDate);
            logger.debug("Before saving user: resetPasswordToken={}, expiryDate={}", resetPasswordToken, expiryDate);

            // Save the user and flush to ensure data is persisted immediately.
            userRepository.save(user);
            userRepository.flush(); // Ensure entity is written to the database.
            logger.debug("User saved: resetPasswordToken={}, expiryDate={}", user.getResetPasswordToken(),
                    user.getResetPasswordTokenExpiryDate());

            // Verify token persistence by fetching the user again.
            Optional<User> savedUser = userRepository.findFirstByEmail(user.getEmail());
            if (savedUser.isPresent()) {
                logger.debug("Fetched user after save: resetPasswordToken={}, expiryDate={}",
                        savedUser.get().getResetPasswordToken(), savedUser.get().getResetPasswordTokenExpiryDate());
            } else {
                logger.error("User not found after save: {}", user.getEmail());
                throw new RuntimeException("Failed to save user during forgot password");
            }

            // Sending the reset password link to the user using the injected base URL.
            String resetLink = baseUrl + "/api/auth/reset-password?token=" + resetPasswordToken;
            Context context = new Context();
            context.setVariable("resetLink", resetLink);
            context.setVariable("isFormPage", false); // For email body template.
            emailService.sendHtmlEmail(email, "Password Reset", "reset-password", context);
            logger.debug("Reset password email sent to: {}", email);
        } else {
            logger.warn("User not found with email: {}", email);
            throw new RuntimeException("User not found with email: " + email);
        }
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        // Retrieve user by reset token and ensure token expiry is valid.
        Optional<User> optionalUser = userRepository.findByResetPasswordToken(token);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.getResetPasswordTokenExpiryDate().isBefore(LocalDateTime.now())) {
                logger.warn("Password reset token expired for user: {}", user.getEmail());
                throw new RuntimeException("Password reset token expired.");
            }
            // Set the new password and clear the reset token and expiry date.
            user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
            user.setResetPasswordToken(null);
            user.setResetPasswordTokenExpiryDate(null);
            userRepository.saveAndFlush(user);
            logger.debug("Password reset for user: {}", user.getEmail());
        } else {
            logger.warn("Invalid password reset token: {}", token);
            throw new RuntimeException("Invalid password reset token.");
        }
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        // Retrieve user by verification token and ensure token expiry is valid.
        Optional<User> optionalUser = userRepository.findByVerificationToken(token);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.getVerificationTokenExpiryDate().isBefore(LocalDateTime.now())) {
                logger.warn("Email verification token expired for user: {}", user.getEmail());
                throw new RuntimeException("Email verification token expired.");
            }
            // Mark the user as verified and clear the verification token.
            user.setVerified(true);
            user.setVerificationToken(null);
            user.setVerificationTokenExpiryDate(null);
            userRepository.saveAndFlush(user);
            logger.debug("Email verified for user: {}", user.getEmail());
        } else {
            logger.warn("Invalid email verification token: {}", token);
            throw new RuntimeException("Invalid email verification token.");
        }
    }

    // Converts the User entity to a UserDto for use in the response.
    private UserDto convertToUserDto(User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setName(user.getName());
        userDto.setUserRole(user.getUserRole());
        return userDto;
    }
}