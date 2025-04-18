package fi.haagahelia.taskmanagement.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import lombok.RequiredArgsConstructor;
import org.springframework.ui.Model;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import fi.haagahelia.taskmanagement.domain.User;
import fi.haagahelia.taskmanagement.utils.JwtUtil;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final JwtUtil jwtUtil; // Utility class for handling JWT token operations

    /**
     * Home page route.
     * Redirects authenticated users to the dashboard, otherwise renders the home
     * page.
     * 
     * @return The name of the view to render.
     */
    @GetMapping("/")
    public String home() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // If the user is authenticated, redirect to the dashboard
        if (auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser")) {
            return "redirect:/dashboard";
        }
        // If not authenticated, return the home page view
        return "home"; // This will render home.html from templates directory
    }

    /**
     * Dashboard route.
     * Checks authentication and retrieves user information either from the JWT
     * token or session.
     * If no valid user is found, redirects to the login form.
     * 
     * @param model   The model to add attributes to the view.
     * @param request The HTTP request for session management.
     * @return The name of the view to render, or a redirect to the login form.
     */
    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpServletRequest request) {
        // Get authentication information
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // Check if the user is authenticated
        if (authentication != null && authentication.isAuthenticated() &&
                !authentication.getPrincipal().equals("anonymousUser")) {

            try {
                // Attempt to retrieve the logged-in user from the JWT token
                User user = jwtUtil.getLoggedInUser();

                if (user == null) {
                    // Fallback to retrieve user from JWT stored in the session
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        String jwt = (String) session.getAttribute("jwt");
                        if (jwt != null) {
                            user = jwtUtil.getUserFromToken(jwt);
                        }
                    }
                }

                // If user is found, add user details to the model and render the dashboard view
                if (user != null) {
                    model.addAttribute("userId", user.getId());
                    model.addAttribute("userRole", user.getUserRole());
                    model.addAttribute("userName", user.getName());
                    return "dashboard";
                }

                // If no valid user found, redirect to the login form
                return "redirect:/api/auth/login-form";
            } catch (Exception e) {
                // In case of an error, redirect to the login form
                return "redirect:/api/auth/login-form";
            }
        }
        // If not authenticated, redirect to the login form
        return "redirect:/api/auth/login-form";
    }

    /**
     * Home page route alias.
     * Redirects to the home page view.
     * 
     * @return The name of the view to render.
     */
    @GetMapping("/home")
    public String homePage() {
        return "home"; // Alias for the home page
    }

    /**
     * About page route.
     * Temporarily using the home page as the about page.
     * 
     * @return The name of the view to render.
     */
    @GetMapping("/about")
    public String about() {
        return "home"; // Temporarily using home page for about as well
    }
}
