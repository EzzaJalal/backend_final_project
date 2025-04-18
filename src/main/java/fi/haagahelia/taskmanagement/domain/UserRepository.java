package fi.haagahelia.taskmanagement.domain;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository interface for User entity with additional query methods.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /** Find user by email (used for login and verification) */
    Optional<User> findFirstByEmail(String email);

    /** Find user by role (used for admin filtering) */
    Optional<User> findByUserRole(UserRole role);

    /** Find user by email verification token */
    Optional<User> findByVerificationToken(String token);

    /** Find user by password reset token */
    Optional<User> findByResetPasswordToken(String token);
}
