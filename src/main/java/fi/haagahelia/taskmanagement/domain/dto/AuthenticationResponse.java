package fi.haagahelia.taskmanagement.domain.dto;

import fi.haagahelia.taskmanagement.domain.UserRole;
import lombok.Data;

@Data
public class AuthenticationResponse {

    // JWT token issued upon successful login
    private String jwt;

    // ID of the authenticated user
    private Long userId;

    // Role of the authenticated user (e.g., ADMIN, EMPLOYEE)
    private UserRole userRole;
}
