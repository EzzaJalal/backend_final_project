package fi.haagahelia.taskmanagement.domain.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AuthenticationRequest {

    // User's email for login, must not be blank and must follow email format
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    // User's password for login, must not be blank
    @NotBlank(message = "Password is required")
    private String password;
}
