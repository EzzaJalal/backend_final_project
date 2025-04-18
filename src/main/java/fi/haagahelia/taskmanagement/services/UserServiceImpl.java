package fi.haagahelia.taskmanagement.services;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import fi.haagahelia.taskmanagement.domain.UserRepository;
import lombok.RequiredArgsConstructor;

// Service implementation for handling user-related operations, specifically for loading user details.
@Service
@RequiredArgsConstructor // Lombok annotation to generate the constructor for dependency injection.
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository; // Dependency to interact with the User repository for fetching user
                                                 // data.

    @Override
    public UserDetailsService userDetailService() {
        // Returning an anonymous implementation of UserDetailsService to load user
        // details by username (email).
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                // Fetching the user by email (username), throwing an exception if the user is
                // not found.
                return userRepository.findFirstByEmail(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
            }
        };
    }
}
