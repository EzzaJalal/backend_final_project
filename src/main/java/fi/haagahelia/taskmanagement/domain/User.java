package fi.haagahelia.taskmanagement.domain;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;
import fi.haagahelia.taskmanagement.domain.dto.UserDto;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a system user (admin or employee).
 * Implements Spring Security's UserDetails interface for authentication.
 */
@Data
@Entity
@Table(name = "app_user")
public class User implements UserDetails {

    private static final Logger logger = LoggerFactory.getLogger(User.class);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Full name of the user */
    private String name;

    /** Unique email address (used as username) */
    private String email;

    /** Encrypted password */
    private String password;

    /** Role of the user (ADMIN or EMPLOYEE) */
    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    /** Email verification token and its expiry */
    @Column(name = "VERIFICATION_TOKEN")
    private String verificationToken;

    @Column(name = "VERIFICATION_TOKEN_EXPIRY_DATE")
    private java.time.LocalDateTime verificationTokenExpiryDate;

    /** Password reset token and its expiry */
    @Column(name = "RESET_PASSWORD_TOKEN")
    private String resetPasswordToken;

    @Column(name = "RESET_PASSWORD_TOKEN_EXPIRY_DATE")
    private java.time.LocalDateTime resetPasswordTokenExpiryDate;

    /** Email verification status */
    @Column(name = "IS_VERIFIED")
    private boolean isVerified = false;

    /** Authorities (roles) for Spring Security */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + userRole.name()));
        logger.debug("Authorities for user {}: {}", email, authorities);
        return authorities;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /** Admins are always enabled; others depend on email verification */
    @Override
    public boolean isEnabled() {
        boolean enabled = (userRole == UserRole.ADMIN) ? true : isVerified;
        logger.debug("User {} isEnabled: {}", email, enabled);
        return enabled;
    }

    /** Converts this User to a lightweight DTO */
    public UserDto getUserDto() {
        UserDto userDto = new UserDto();
        userDto.setId(id);
        userDto.setName(name);
        userDto.setEmail(email);
        userDto.setUserRole(userRole);
        return userDto;
    }
}
