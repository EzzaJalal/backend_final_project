package fi.haagahelia.taskmanagement.domain.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class SignupRequest {

    // Full name of the user, required during registration
    @NotBlank(message = "Name is required")
    private String name;

    // Email of the user, required and must follow valid format
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    // Password chosen by the user for authentication, required
    @NotBlank(message = "Password is required")
    private String password;
}
