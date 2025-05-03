package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.DelegateRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleRequest;
import com.codejam.codex.authzen.dtos.inputs.RoleUpdateRequest;
import com.codejam.codex.authzen.dtos.outputs.AuditLogResponse;
import com.codejam.codex.authzen.dtos.outputs.UpdateUserResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.endpoint.AdminEndpoint;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Objects;

/**
 * AdminController handles administrative actions such as user management, role assignments,
 * audit log access, and permission delegation. Access is restricted to users with ROLE_ADMIN.
 */
@RestController
@RequestMapping(ApiEndpoint.ADMIN)
@PreAuthorize("hasRole('ROLE_ADMIN')")
public class AdminController {

    private final AdminEndpoint adminEndpoint;
    private final AuthEndpoint authEndpoint;

    public AdminController(AdminEndpoint adminEndpoint, AuthEndpoint authEndpoint) {
        this.adminEndpoint = adminEndpoint;
        this.authEndpoint = authEndpoint;
    }

    private String verifyAdmin(HttpServletRequest request) {
        String username = authEndpoint.getUsername(request);
        if (username == null || !authEndpoint.isAuthenticated(request)) {
            throw new AccessDeniedException("Unauthorized: Invalid or missing token");
        }

        UserResponse userResponse = authEndpoint.getUserDetails(username);
        if (userResponse == null || !userResponse.getRoles().contains("ROLE_ADMIN")) {
            throw new AccessDeniedException("Forbidden: User does not have admin privileges");
        }

        return username;
    }

    @GetMapping(ApiEndpoint.ADMIN_ALL_USERS)
    @PreAuthorize("hasAuthority('VIEW_USER')")
    public ResponseEntity<AuthzenResponse<List<UserResponse>>> getAllUsers(HttpServletRequest request) {
        String username = verifyAdmin(request);
        List<UserResponse> users = adminEndpoint.getAllUsers(username);
        AuthzenResponse<List<UserResponse>> response = new AuthzenResponse<>(users);
        response.setMessage("Users retrieved successfully");
        return ResponseEntity.ok(response);
    }

    @GetMapping(ApiEndpoint.ADMIN_USERS)
    @PreAuthorize("hasAuthority('VIEW_USER')")
    public ResponseEntity<AuthzenResponse<UserResponse>> getUserDetails(@PathVariable("id") Long userId, HttpServletRequest request) {
        verifyAdmin(request);
        UserResponse userResponse = adminEndpoint.getUserById(userId);
        if (userResponse == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new AuthzenResponse<>(null, false, "User not found"));
        }
        AuthzenResponse<UserResponse> response = new AuthzenResponse<>(userResponse);
        response.setMessage("User details retrieved successfully");
        return ResponseEntity.ok(response);
    }

    @PutMapping(ApiEndpoint.ADMIN_USER_ROLES)
    @PreAuthorize("hasAuthority('UPDATE_USER')")
    public ResponseEntity<AuthzenResponse<UpdateUserResponse>> updateUserRole(
            @PathVariable("id") Long userId,
            @RequestBody @Valid RoleUpdateRequest roleUpdateRequest,
            HttpServletRequest request) {
        String username = verifyAdmin(request);
        UpdateUserResponse updated = adminEndpoint.updateUserRoles(userId, roleUpdateRequest, username);
        AuthzenResponse<UpdateUserResponse> response = new AuthzenResponse<>(updated);
        response.setMessage("User roles updated successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping(ApiEndpoint.ADMIN_ROLES)
    @PreAuthorize("hasAuthority('CREATE_ROLE')") // Fixed permission from CREATE_USER to CREATE_ROLE
    public ResponseEntity<AuthzenResponse<String>> createRole(
            @RequestBody @Valid RoleRequest roleRequest,
            HttpServletRequest request) {
        String username = verifyAdmin(request);
        String created = adminEndpoint.createRole(roleRequest, username);
        AuthzenResponse<String> response = new AuthzenResponse<>();
        response.setMessage(created);
        return ResponseEntity.ok(response);
    }

    @GetMapping(ApiEndpoint.ADMIN_AUDIT_LOGS)
    @PreAuthorize("hasAuthority('VIEW_AUDIT_LOG')") // Fixed permission from VIEW_USER to VIEW_AUDIT_LOG
    public ResponseEntity<AuthzenResponse<List<AuditLogResponse>>> getAuditLogs(HttpServletRequest request) {
        String username = verifyAdmin(request);
        List<AuditLogResponse> auditLogs = adminEndpoint.getAuditLogs(username);
        AuthzenResponse<List<AuditLogResponse>> response = new AuthzenResponse<>(auditLogs);
        response.setMessage("Audit logs retrieved successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping(ApiEndpoint.ADMIN_DELEGATE)
    @PreAuthorize("hasAuthority('UPDATE_USER')")
    public ResponseEntity<AuthzenResponse<String>> delegatePermissions(
            @RequestBody @Valid DelegateRequest delegateRequest,
            HttpServletRequest request) {
        String username = verifyAdmin(request);
        String delegated = adminEndpoint.delegatePermissions(delegateRequest, username);
        AuthzenResponse<String> response = new AuthzenResponse<>();
        response.setMessage(delegated);
        return ResponseEntity.ok(response);
    }
}