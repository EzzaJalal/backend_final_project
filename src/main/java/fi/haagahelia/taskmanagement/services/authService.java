package fi.haagahelia.taskmanagement.services;

import fi.haagahelia.taskmanagement.domain.dto.AuthenticationRequest;
import fi.haagahelia.taskmanagement.domain.dto.AuthenticationResponse;
import fi.haagahelia.taskmanagement.domain.dto.SignupRequest;
import fi.haagahelia.taskmanagement.domain.dto.UserDto;

/**
 * Service interface for handling user authentication and registration.
 */
public interface authService {

    /**
     * Registers a new user by processing the signup request.
     * 
     * @param signupRequest - The details required for user registration.
     * @return UserDto - The details of the newly registered user.
     */
    UserDto signupUser(SignupRequest signupRequest);

    /**
     * Authenticates a user based on the provided credentials.
     * 
     * @param authenticationRequest - The authentication request with email and
     *                              password.
     * @return AuthenticationResponse - The JWT token and user details if
     *         authentication is successful.
     */
    AuthenticationResponse login(AuthenticationRequest authenticationRequest);

    /**
     * Checks if a user with the given email exists in the system.
     * 
     * @param email - The email to check.
     * @return boolean - Returns true if the user exists, otherwise false.
     */
    boolean hasUserWithEmail(String email);

    /**
     * Initiates a password recovery process by sending a password reset email.
     * 
     * @param email - The email of the user requesting the password reset.
     */
    void forgotPassword(String email);

    /**
     * Resets the password of the user identified by the given token.
     * 
     * @param token       - The password reset token.
     * @param newPassword - The new password to set for the user.
     */
    void resetPassword(String token, String newPassword);

    /**
     * Verifies the user's email using the provided token.
     * 
     * @param token - The email verification token.
     */
    void verifyEmail(String token);
}
