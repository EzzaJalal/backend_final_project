package fi.haagahelia.taskmanagement.utils;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.apache.commons.lang3.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import fi.haagahelia.taskmanagement.services.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String JWT_SESSION_ATTR = "jwt";

    private final JwtUtil jwtUtil;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // List of routes to exclude from JWT authentication
        List<String> excludedRoutes = List.of(
                "/", "/home", "/about", "/login", "/signup", "/forgot-password",
                "/reset-password", "/email-verification",
                "/css/**", "/js/**", "/images/**", "/favicon.ico",
                "/h2-console/**",
                "/logout",
                "/api/auth/**");

        // Get the request URI
        String requestURI = request.getRequestURI();
        logger.debug("Processing request URI: {}", requestURI);

        // Skip JWT authentication for excluded routes
        boolean isExcluded = excludedRoutes.stream().anyMatch(route -> {
            if (route.endsWith("/**")) {
                String baseRoute = route.substring(0, route.length() - 3);
                return requestURI.startsWith(baseRoute);
            }
            return requestURI.equals(route);
        });

        if (isExcluded) {
            logger.debug("Request URI {} is excluded from JWT authentication", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        // Try to get the JWT token from multiple sources
        String jwt = null;

        // 1. Check Authorization header
        final String authHeader = request.getHeader("Authorization");
        if (!StringUtils.isEmpty(authHeader) && StringUtils.startsWith(authHeader, "Bearer ")) {
            jwt = authHeader.substring(7);
            logger.debug("Found JWT token in Authorization header");
        }

        // 2. If not found in header, check session
        if (jwt == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                Object jwtObj = session.getAttribute(JWT_SESSION_ATTR);
                if (jwtObj != null) {
                    jwt = jwtObj.toString();
                    logger.debug("Found JWT token in session");
                }
            }
        }

        // 3. If not found in session, check cookies
        if (jwt == null && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("jwt")) {
                    jwt = cookie.getValue();
                    logger.debug("Found JWT token in cookie");
                    break;
                }
            }
        }

        // If no JWT token found, continue the filter chain
        if (jwt == null) {
            logger.debug("No JWT token found for URI: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        final String userEmail = jwtUtil.extractUserName(jwt);
        logger.debug("Extracted user email from token: {}", userEmail);

        if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.userDetailService().loadUserByUsername(userEmail);
            logger.debug("UserDetails loaded: enabled={}, authorities={}", userDetails.isEnabled(),
                    userDetails.getAuthorities());
            if (jwtUtil.isTokenValid(jwt, userDetails)) {
                if (!userDetails.isEnabled()) {
                    logger.warn("User {} is not verified. Access denied for URI: {}", userEmail, requestURI);
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("User account is not verified. Please verify your email to proceed.");
                    return;
                }

                // Check if trying to access admin pages with non-admin role
                if (requestURI.startsWith("/api/admin")) {
                    boolean isAdmin = userDetails.getAuthorities().stream()
                            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

                    if (!isAdmin) {
                        logger.warn("Non-admin user {} attempted to access admin route: {}", userEmail, requestURI);
                        response.sendRedirect("/api/auth/access-denied");
                        return;
                    }
                }

                List<String> roles = jwtUtil.extractRoles(jwt);
                if (roles == null || roles.isEmpty()) {
                    // If no roles in token, get them from UserDetails
                    roles = userDetails.getAuthorities().stream()
                            .map(authority -> authority.getAuthority())
                            .collect(Collectors.toList());

                    if (roles == null || roles.isEmpty()) {
                        logger.error("No roles found for user {} in token or userDetails. Access denied for URI: {}",
                                userEmail, requestURI);
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("No roles found in token or userDetails. Access denied.");
                        return;
                    }
                }

                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, authorities);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.debug("Authentication set for user: {}", userEmail);
            } else {
                logger.warn("Invalid or expired token for user {}. Access denied for URI: {}", userEmail, requestURI);
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("Invalid or expired token. Please log in again.");
                return;
            }
        } else {
            logger.debug("User email is empty or authentication already exists for URI: {}", requestURI);
        }
        filterChain.doFilter(request, response);
    }
}