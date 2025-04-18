package fi.haagahelia.taskmanagement.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

import fi.haagahelia.taskmanagement.domain.dto.AuthenticationRequest;
import fi.haagahelia.taskmanagement.domain.dto.AuthenticationResponse;
import fi.haagahelia.taskmanagement.domain.dto.SignupRequest;
import fi.haagahelia.taskmanagement.services.authService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;

@Controller
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin("*")
public class AuthController {

    private final authService authService; // Service responsible for authentication logic
    private static final String JWT_SESSION_ATTR = "jwt"; // Constant for JWT session attribute

    /**
     * REST API Endpoints
     */

    /**
     * Endpoint to handle user registration.
     * 
     * @param signupRequest The signup request containing user details.
     * @return Response indicating success or failure.
     */
    @PostMapping(value = "/signup", produces = "application/json")
    @ResponseBody
    public ResponseEntity<?> signupUser(@RequestBody SignupRequest signupRequest) {
        if (authService.hasUserWithEmail(signupRequest.getEmail())) {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body("User already exists with this email");
        }
        authService.signupUser(signupRequest); // Proceed with user signup
        return ResponseEntity.status(HttpStatus.CREATED).build(); // Return success status
    }

    /**
     * Endpoint to handle user login.
     * 
     * @param authenticationRequest Contains user credentials (email and password).
     * @return Authentication response with JWT token.
     */
    @PostMapping(value = "/login", produces = "application/json")
    @ResponseBody
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest authenticationRequest) {
        AuthenticationResponse response = authService.login(authenticationRequest); // Perform login and get JWT
                                                                                    // response
        return ResponseEntity.ok(response); // Return JWT token in response
    }

    /**
     * Endpoint to verify email using the provided token.
     * 
     * @param token The verification token sent to the user.
     * @return Response indicating success of email verification.
     */
    @GetMapping(value = "/verify-email", produces = "application/json")
    @ResponseBody
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token); // Verify email based on the token
        return ResponseEntity.ok("Email verified successfully."); // Return success response
    }

    /**
     * Endpoint to handle forgot password functionality.
     * 
     * @param email The email to send the password reset link to.
     * @return Response indicating whether the reset link was successfully sent.
     */
    @PostMapping(value = "/forgot-password", produces = "application/json")
    @ResponseBody
    public ResponseEntity<String> forgotPassword(@RequestParam String email) {
        try {
            authService.forgotPassword(email); // Send password reset link
            return ResponseEntity.ok("Password reset link sent to your email.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage()); // Handle failure
        }
    }

    /**
     * Endpoint to reset the password with the provided token and new password.
     * 
     * @param token       The password reset token.
     * @param newPassword The new password to set.
     * @return Response indicating success or failure of the password reset.
     */
    @PostMapping(value = "/reset-password", produces = "application/json")
    @ResponseBody
    public ResponseEntity<String> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        try {
            authService.resetPassword(token, newPassword); // Reset the password
            return ResponseEntity.ok("Password reset successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage()); // Handle failure
        }
    }

    /**
     * Thymeleaf Views
     */

    /**
     * Shows the login form for the user to input login credentials.
     * 
     * @param model The model to be passed to the view.
     * @return Name of the login view template.
     */
    @GetMapping("/login-form")
    public String showLoginForm(Model model) {
        model.addAttribute("authenticationRequest", new AuthenticationRequest()); // Add an empty AuthenticationRequest
                                                                                  // to the model
        return "login"; // Return the login page
    }

    /**
     * Handles user authentication after form submission.
     * 
     * @param request         The login request with email and password.
     * @param bindingResult   Holds validation results.
     * @param model           The model to pass to the view.
     * @param servletRequest  The HTTP request object.
     * @param servletResponse The HTTP response object.
     * @return Name of the view to show after login attempt.
     */
    @PostMapping("/login-form")
    public String authenticateUser(@Valid @ModelAttribute("authenticationRequest") AuthenticationRequest request,
            BindingResult bindingResult, Model model, HttpServletRequest servletRequest,
            HttpServletResponse servletResponse) {
        if (bindingResult.hasErrors()) {
            return "login"; // Return login page if there are validation errors
        }

        try {
            AuthenticationResponse response = authService.login(request); // Perform login and get JWT response

            // Store JWT token in session for authentication persistence
            HttpSession session = servletRequest.getSession(true);
            session.setAttribute(JWT_SESSION_ATTR, response.getJwt());

            // Also store JWT as an HTTP-only cookie for additional support
            Cookie jwtCookie = new Cookie("jwt", response.getJwt());
            jwtCookie.setPath("/"); // Ensure it is available across the entire application
            jwtCookie.setHttpOnly(true); // Make cookie accessible only via HTTP
            jwtCookie.setMaxAge(24 * 60 * 60); // Set cookie expiration to 1 day
            servletResponse.addCookie(jwtCookie);

            return "redirect:/dashboard"; // Redirect to dashboard after successful login
        } catch (Exception e) {
            model.addAttribute("error", "Invalid email or password"); // Show error on login failure
            return "login"; // Return login page
        }
    }

    /**
     * Shows the signup form for the user to register.
     * 
     * @param model The model to pass to the view.
     * @return Name of the signup view template.
     */
    @GetMapping("/signup-form")
    public String showSignupForm(Model model) {
        model.addAttribute("signupRequest", new SignupRequest()); // Add an empty SignupRequest to the model
        return "signup"; // Return the signup page
    }

    /**
     * Handles user registration after form submission.
     * 
     * @param request       The signup request containing user details.
     * @param bindingResult Holds validation results.
     * @param model         The model to pass to the view.
     * @return Name of the view to show after signup attempt.
     */
    @PostMapping("/signup-form")
    public String registerUser(@Valid @ModelAttribute("signupRequest") SignupRequest request,
            BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "signup"; // Return signup page if there are validation errors
        }

        try {
            if (authService.hasUserWithEmail(request.getEmail())) {
                model.addAttribute("error", "User already exists with this email"); // Show error if user already exists
                return "signup";
            }
            authService.signupUser(request); // Proceed with user registration
            model.addAttribute("success", "User registered successfully. Please check your email for verification.");
            return "signup-success"; // Return success page after registration
        } catch (Exception e) {
            model.addAttribute("error", "Failed to register user. Please try again."); // Show error if registration
                                                                                       // fails
            return "signup"; // Return signup page on failure
        }
    }

    /**
     * Shows the forgot password form.
     * 
     * @param model The model to pass to the view.
     * @return Name of the forgot password view template.
     */
    @GetMapping("/forgot-password")
    public String showForgotPasswordForm(Model model) {
        return "forgot-password"; // Return the forgot-password page
    }

    /**
     * Handles forgot password form submission.
     * 
     * @param email The email to send the password reset link to.
     * @param model The model to pass to the view.
     * @return Name of the view to show after forgot password attempt.
     */
    @PostMapping("/forgot-password-form")
    public String handleForgotPasswordForm(@RequestParam String email, Model model) {
        try {
            authService.forgotPassword(email); // Send password reset link to the provided email
            model.addAttribute("success", "Password reset link sent to your email.");
            return "forgot-password"; // Return the forgot-password page with success message
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage()); // Show error if sending the reset link fails
            return "forgot-password"; // Return forgot-password page with error message
        }
    }

    /**
     * Shows the reset password form for the user to input new password.
     * 
     * @param token The reset token.
     * @param model The model to pass to the view.
     * @return Name of the reset password view template.
     */
    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam String token, Model model) {
        model.addAttribute("token", token); // Add reset token to the model
        model.addAttribute("isFormPage", true); // Indicate that this is a form page
        return "reset-password"; // Return reset-password page
    }

    /**
     * Handles reset password form submission.
     * 
     * @param token           The reset token.
     * @param newPassword     The new password to set.
     * @param confirmPassword The confirmation of the new password.
     * @param model           The model to pass to the view.
     * @return Name of the view to show after reset password attempt.
     */
    @PostMapping("/reset-password-form")
    public String handleResetPasswordForm(
            @RequestParam String token,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            Model model) {
        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords do not match."); // Show error if passwords don't match
            model.addAttribute("isFormPage", true);
            return "reset-password"; // Return reset-password page with error
        }
        try {
            authService.resetPassword(token, newPassword); // Proceed with password reset
            model.addAttribute("success", "Password reset successfully. You can now log in with your new password.");
            model.addAttribute("isFormPage", true);
            return "reset-password"; // Return reset-password page with success message
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage()); // Show error if resetting password fails
            model.addAttribute("isFormPage", true);
            return "reset-password"; // Return reset-password page with error message
        }
    }

    /**
     * Displays the email verification page.
     * 
     * @param token The verification token.
     * @param model The model to pass to the view.
     * @return Name of the email verification view template.
     */
    @GetMapping("/verify-email-view")
    public String showVerifyEmailView(@RequestParam String token, Model model) {
        try {
            authService.verifyEmail(token); // Verify email using the token
            model.addAttribute("isSuccessPage", true); // Indicate success page
            return "email-verification"; // Return email-verification page
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage()); // Show error if verification fails
            return "error"; // Return error page on failure
        }
    }

    /**
     * Handles logout by invalidating session and clearing JWT cookie.
     * 
     * @param request  The HTTP request.
     * @param response The HTTP response.
     * @return Redirect URL after logout.
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        // Invalidate session
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate(); // Invalidate session
        }

        // Clear JWT cookie
        Cookie jwtCookie = new Cookie("jwt", null);
        jwtCookie.setPath("/"); // Make cookie invalid for all paths
        jwtCookie.setMaxAge(0); // Expire the cookie immediately
        response.addCookie(jwtCookie); // Add the expired cookie to the response

        // Clear security context
        SecurityContextHolder.clearContext(); // Clear the authentication context

        return "redirect:/home"; // Redirect to home page after logout
    }

    /**
     * Displays the access denied page.
     * 
     * @param model The model to pass to the view.
     * @return Name of the access denied view template.
     */
    @GetMapping("/access-denied")
    public String accessDenied(Model model) {
        model.addAttribute("error",
                "You don't have permission to access this page. Please log in with an admin account.");
        return "access-denied"; // Return access-denied page
    }
}
