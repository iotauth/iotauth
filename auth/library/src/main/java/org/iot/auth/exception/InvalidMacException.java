package org.iot.auth.exception;

/**
 * Exception thrown when there is an integrity error in MAC (Message Authentication Code).
 * @author Hokeun Kim
 */
public class InvalidMacException extends Exception {
    /**
     * Create a new InvalidMacException with the given message.
     * @param message The given message.
     */
    public InvalidMacException(String message) {
        super(message);
    }
}

