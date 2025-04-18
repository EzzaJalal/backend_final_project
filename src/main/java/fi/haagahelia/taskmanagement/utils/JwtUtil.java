package fi.haagahelia.taskmanagement.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import fi.haagahelia.taskmanagement.domain.User;
import fi.haagahelia.taskmanagement.domain.UserRepository;

import java.util.Optional;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private final UserRepository userRepository;

    @Value("${app.jwt.secret}")
    private String SECRET_KEY;

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        // Store the role name without ROLE_ prefix in the token
        List<String> roles = userDetails.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .map(authority -> authority.startsWith("ROLE_") ? authority.substring(5) : authority)
                .collect(Collectors.toList());
        claims.put("roles", roles);
        logger.debug("Generating token for user: {}, with roles: {}", userDetails.getUsername(), roles);
        return generateToken(claims, userDetails);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        try {
            List<String> roles = extractClaim(token, claims -> (List<String>) claims.get("roles"));
            
            if (roles != null) {
                // Always ensure roles have ROLE_ prefix for Spring Security
                return roles.stream()
                        .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                        .collect(Collectors.toList());
            } else {
                logger.warn("No roles found in token");
                return null;
            }
        } catch (Exception e) {
            logger.error("Error extracting roles from token: {}", e.getMessage());
            return null;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Updated getLoggedInUser() method.
     * If the authentication principal is not a direct User instance,
     * load the user by username (email) from the repository.
     */
    public User getLoggedInUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof User) {
                User user = (User) principal;
                // Optionally, refresh the user from the repository
                Optional<User> optionalUser = userRepository.findById(user.getId());
                logger.debug("Logged in user (from principal): {}", optionalUser.orElse(null));
                return optionalUser.orElse(null);
            } else if (principal instanceof UserDetails) {
                String email = ((UserDetails) principal).getUsername();
                Optional<User> optionalUser = userRepository.findFirstByEmail(email);
                logger.debug("Logged in user (loaded by email): {}", optionalUser.orElse(null));
                return optionalUser.orElse(null);
            }
        }
        logger.debug("No authenticated user found in SecurityContext");
        return null;
    }
    
    /**
     * Extracts user information from JWT token
     * @param token The JWT token
     * @return User object if found, null otherwise
     */
    public User getUserFromToken(String token) {
        try {
            String email = extractUserName(token);
            if (email != null) {
                Optional<User> optionalUser = userRepository.findFirstByEmail(email);
                logger.debug("User extracted from token: {}", optionalUser.orElse(null));
                return optionalUser.orElse(null);
            }
        } catch (Exception e) {
            logger.error("Error extracting user from token: {}", e.getMessage());
        }
        return null;
    }
}
