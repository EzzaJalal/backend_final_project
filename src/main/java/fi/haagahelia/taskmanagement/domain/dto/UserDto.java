package fi.haagahelia.taskmanagement.domain.dto;

import fi.haagahelia.taskmanagement.domain.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserDto {

    // Unique identifier for the user
    private Long id;

    // Full name of the user, must not be blank
    @NotBlank(message = "Name is required")
    private String name;

    // Email of the user, required and must be valid
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    // Optional password (may be excluded from responses for security)
    private String password;

    // Role assigned to the user (e.g., ADMIN, EMPLOYEE)
    private UserRole userRole;

    // Whether the user has verified their account
    private boolean verified;
}
