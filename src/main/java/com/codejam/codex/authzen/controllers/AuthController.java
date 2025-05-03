package com.codejam.codex.authzen.controllers;

import com.codejam.codex.authzen.constants.ApiEndpoint;
import com.codejam.codex.authzen.dtos.inputs.*;
import com.codejam.codex.authzen.dtos.outputs.TokenResponse;
import com.codejam.codex.authzen.dtos.outputs.UserResponse;
import com.codejam.codex.authzen.responses.AuthzenResponse;
import com.codejam.codex.authzen.endpoint.AuthEndpoint;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiEndpoint.AUTH)
public class AuthController {

    private final AuthEndpoint authEndpoint;

    public AuthController(AuthEndpoint authEndpoint) {
        this.authEndpoint = authEndpoint;
    }

    @PostMapping(ApiEndpoint.AUTH_REGISTER)
    public ResponseEntity<AuthzenResponse<UserResponse>> register(@RequestBody @Valid RegisterRequest request) {
        try {
            UserResponse userResponse = authEndpoint.registerUser(request);
            AuthzenResponse<UserResponse> response = new AuthzenResponse<>(userResponse);
            response.setMessage("User registered successfully");
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthzenResponse<>(null, false, "Invalid registration data: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "Registration failed: " + e.getMessage()));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_LOGIN)
    public ResponseEntity<AuthzenResponse<TokenResponse>> login(@RequestBody @Valid LoginRequest request) {
        try {
            TokenResponse token = authEndpoint.authenticateUser(request);
            if (token != null) {
                AuthzenResponse<TokenResponse> response = new AuthzenResponse<>(token);
                response.setMessage("User logged in successfully");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Invalid credentials"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthzenResponse<>(null, false, "Invalid login data: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "Login failed: " + e.getMessage()));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_OAUTH)
    public ResponseEntity<AuthzenResponse<TokenResponse>> oauthLogin(@RequestBody @Valid OAuthRequest request) {
        try {
            TokenResponse oauthToken = authEndpoint.authenticateOAuth(request);
            if (oauthToken != null) {
                AuthzenResponse<TokenResponse> response = new AuthzenResponse<>(oauthToken);
                response.setMessage("OAuth login successful");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "OAuth login failed"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthzenResponse<>(null, false, "Invalid OAuth data: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "OAuth login failed: " + e.getMessage()));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_RESET_REQUEST)
    public ResponseEntity<AuthzenResponse<Object>> resetPasswordRequest(@RequestBody @Valid ResetRequest request) {
        try {
            boolean emailSent = authEndpoint.sendPasswordResetEmail(request);
            if (emailSent) {
                AuthzenResponse<Object> response = new AuthzenResponse<>();
                response.setMessage("Password reset email sent successfully");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new AuthzenResponse<>(null, false, "Failed to send reset email"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthzenResponse<>(null, false, "Invalid reset request: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "Failed to process reset request: " + e.getMessage()));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_RESET_PASSWORD)
    public ResponseEntity<AuthzenResponse<Object>> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        try {
            boolean isPasswordReset = authEndpoint.resetUserPassword(request);
            if (isPasswordReset) {
                AuthzenResponse<Object> response = new AuthzenResponse<>();
                response.setMessage("Password reset successfully");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new AuthzenResponse<>(null, false, "Failed to reset password"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthzenResponse<>(null, false, "Invalid reset data: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "Password reset failed: " + e.getMessage()));
        }
    }

    @PostMapping(ApiEndpoint.AUTH_REFRESH)
    public ResponseEntity<AuthzenResponse<TokenResponse>> refreshToken(@RequestBody @Valid RefreshTokenRequest request) {
        try {
            TokenResponse tokenResponse = authEndpoint.refreshToken(request.getRefreshToken());
            if (tokenResponse != null) {
                AuthzenResponse<TokenResponse> response = new AuthzenResponse<>(tokenResponse);
                response.setMessage("Token refreshed successfully");
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new AuthzenResponse<>(null, false, "Invalid refresh token"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthzenResponse<>(null, false, "Invalid refresh token: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthzenResponse<>(null, false, "Token refresh failed: " + e.getMessage()));
        }
    }
}