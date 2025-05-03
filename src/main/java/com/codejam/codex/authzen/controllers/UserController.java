package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.UpdateUserRequest;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import com.codejam.codex.authzen.endpoint.UserEndpoint;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiEndpoint.USER)
@PreAuthorize("hasRole('ROLE_USER')")
public class UserController {

    private final AuthEndpoint authEndpoint;
    private final UserEndpoint userEndpoint;

    public UserController(AuthEndpoint authEndpoint, UserEndpoint userEndpoint) {
        this.authEndpoint = authEndpoint;
        this.userEndpoint = userEndpoint;
    }

    @GetMapping(ApiEndpoint.AUTH_ME)
    @PreAuthorize("hasAuthority('VIEW_USER')")
    public ResponseEntity<AuthzenResponse<UserResponse>> getProfile(HttpServletRequest request) {
        if (!authEndpoint.isAuthenticated(request)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token"));
        }

        String username = authEndpoint.getUsername(request);
        if (username == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthzenResponse<>(null, false, "Unauthorized: Cannot extract username"));
        }

        UserResponse profile = userEndpoint.getProfile(username);
        if (profile == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new AuthzenResponse<>(null, false, "User profile not found"));
        }

        AuthzenResponse<UserResponse> response = new AuthzenResponse<>(profile);
        response.setMessage("User profile retrieved successfully");
        return ResponseEntity.ok(response);
    }

    @PutMapping(ApiEndpoint.AUTH_UPDATE)
    @PreAuthorize("hasAuthority('UPDATE_USER')")
    public ResponseEntity<AuthzenResponse<UpdateUserResponse>> updateProfile(
            HttpServletRequest request,
            @RequestBody @Valid UpdateUserRequest updateRequest) {
        if (!authEndpoint.isAuthenticated(request)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token"));
        }

        String username = authEndpoint.getUsername(request);
        if (username == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthzenResponse<>(null, false, "Unauthorized: Cannot extract username"));
        }

        UpdateUserResponse updateUserResponse = userEndpoint.updateUser(username, updateRequest);
        AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(updateUserResponse);
        response.setMessage("User profile updated successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping(ApiEndpoint.AUTH_LOGOUT)
    @PreAuthorize("hasAuthority('USER_LOGOUT')")
    public ResponseEntity<AuthzenResponse<Object>> logout(HttpServletRequest request) {
        if (!authEndpoint.isAuthenticated(request)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthzenResponse<>(null, false, "Unauthorized: Invalid or missing token"));
        }

        boolean blacklisted = authEndpoint.blacklistToken(request);
        if (blacklisted) {
            AuthzenResponse<Object> response = new AuthzenResponse<>();
            response.setMessage("User logged out successfully");
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "Failed to blacklist token"));
        }
    }
}