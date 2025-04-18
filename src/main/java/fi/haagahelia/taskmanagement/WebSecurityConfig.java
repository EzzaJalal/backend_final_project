package fi.haagahelia.taskmanagement;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import fi.haagahelia.taskmanagement.services.UserService;
import fi.haagahelia.taskmanagement.utils.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity // Enables Spring Security’s web security support
@EnableMethodSecurity // Allows method-level security annotations like @PreAuthorize
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;

    /**
     * Configures the security filter chain for the application.
     * Defines which endpoints are secured and how requests are handled.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS support
                .csrf(csrf -> csrf.disable()) // Disable CSRF for stateless APIs (enable if needed)
                .authorizeHttpRequests(request -> request
                        // Public endpoints that do not require authentication
                        .requestMatchers(
                                "/login", "/signup", "/forgot-password", "/reset-password", "/email-verification",
                                "favicon.ico", "/api/auth/**", "/h2-console/**", "/", "/home", "/about",
                                "/css/**", "/js/**", "/images/**")
                        .permitAll()
                        // Only authenticated users can access the dashboard
                        .requestMatchers("/dashboard").authenticated()
                        // Only users with ADMIN role can access admin API
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        // Users with EMPLOYEE or ADMIN role can access employee API
                        .requestMatchers("/api/employee/**").hasAnyRole("EMPLOYEE", "ADMIN")
                        // All other requests must be authenticated
                        .anyRequest().authenticated())
                // Handles access denied errors and redirects to a custom page
                .exceptionHandling(handling -> handling
                        .accessDeniedPage("/api/auth/access-denied")
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendRedirect("/api/auth/access-denied");
                        }))
                // Configures logout functionality
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/api/auth/login-form")
                        .permitAll())
                // Creates a session for each request (consider stateless for APIs)
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                // Registers authentication provider
                .authenticationProvider(authenticationProvider())
                // Adds custom JWT filter before the username/password authentication filter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Defines the CORS configuration for allowing cross-origin requests.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // Allow all origins (customize in production)
        configuration.addAllowedMethod("*"); // Allow all HTTP methods (GET, POST, etc.)
        configuration.addAllowedHeader("*"); // Allow all headers
        configuration.setAllowCredentials(true); // Allow cookies and credentials
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Apply to all routes
        return source;
    }

    /**
     * Provides the password encoder bean using BCrypt hashing algorithm.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures the authentication provider with user details service and password
     * encoder.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userService.userDetailService()); // Set custom user service
        authProvider.setPasswordEncoder(passwordEncoder()); // Set password encoder
        return authProvider;
    }

    /**
     * Exposes the authentication manager bean used for processing authentication
     * requests.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
