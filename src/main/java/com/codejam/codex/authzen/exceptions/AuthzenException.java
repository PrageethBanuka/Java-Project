package com.codejam.codex.authzen.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Custom exception class for handling Authzen-specific exceptions.
 * Extends the base {@link Exception} class.
 */
@Getter
public class AuthzenException extends Exception {
    // HTTP status associated with the exception
    private final HttpStatus status;

    /**
     * Constructor for creating an AuthzenException.
     *
     * @param message The error message describing the exception.
     * @param status  The HTTP status code associated with the exception.
     */
    public AuthzenException(String message, HttpStatus status) {
        super(message); // Call the parent Exception class constructor with the message
        this.status = status; // Set the HTTP status
    }
}
