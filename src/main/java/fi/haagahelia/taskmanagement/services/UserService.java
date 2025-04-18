package fi.haagahelia.taskmanagement.services;

import org.springframework.security.core.userdetails.UserDetailsService;

// Interface defining the contract for user-related service operations, specifically loading user details.
public interface UserService {
    // Method signature for retrieving a UserDetailsService implementation, which is
    // responsible for user authentication.
    UserDetailsService userDetailService();
}
