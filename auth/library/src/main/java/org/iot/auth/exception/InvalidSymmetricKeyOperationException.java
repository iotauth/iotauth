package org.iot.auth.exception;

/**
 * Exception thrown when the symmetric key operation is invalid.
 */
public class InvalidSymmetricKeyOperationException extends Exception {
    /**
     * Create a new InvalidMacException with the given message.
     * @param message The given message.
     */
    public InvalidSymmetricKeyOperationException(String message) {
        super(message);
    }
}
