package com.codejam.codex.authzen.configs;

import com.codejam.codex.authzen.models.Role;
import com.codejam.codex.authzen.models.User;
import com.codejam.codex.authzen.models.UserRole;
import com.codejam.codex.authzen.repositories.RoleRepository;
import com.codejam.codex.authzen.repositories.UserRepository;
import com.codejam.codex.authzen.repositories.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

@Configuration
@RequiredArgsConstructor
public class RoleInitializer {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.email:admin@example.com}")
    private String adminEmail;

    @Value("${admin.username:admin}")
    private String adminUsername;

    @Value("${admin.password:Admin123!}")
    private String adminPassword;

    @Bean
    CommandLineRunner initializeRolesAndAdmin() {
        return args -> {
            try {
                // Validate admin properties
                if (adminEmail.isBlank() || adminUsername.isBlank() || adminPassword.isBlank()) {
                    throw new IllegalStateException("Admin email, username, or password is missing or empty");
                }

                Role userRole = createOrGetRole("ROLE_USER", "Default user role");
                Role adminRole = createOrGetRole("ROLE_ADMIN", "Administrator with full access");

                createAdminUserIfNotExists(adminRole);
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize roles and admin: " + e.getMessage(), e);
            }
        };
    }

    private Role createOrGetRole(String name, String description) {
        Optional<Role> existingRole = roleRepository.findByName(name).stream().findFirst();
        if (existingRole.isPresent()) {
            return existingRole.get();
        }

        Role newRole = Role.builder()
                .name(name)
                .description(description)
                .build();
        return roleRepository.save(newRole);
    }

    private void createAdminUserIfNotExists(Role adminRole) {
        Optional<User> existingUser = userRepository.findByEmail(adminEmail);
        if (existingUser.isEmpty()) {
            User admin = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .isActive(true)
                    .isLocked(false)
                    .createdAt(Timestamp.from(Instant.now()))
                    .build();

            User savedAdmin = userRepository.save(admin);

            UserRole userRole = new UserRole();
            userRole.setUser(savedAdmin);
            userRole.setRole(adminRole);
            userRoleRepository.save(userRole);
        }
    }
}