package org.iot.auth.exception;

/**
 * Exception thrown when there is an integrity error in signature (in public key cryptography).
 * @author Hokeun Kim
 */
public class InvalidSignatureException extends Exception {
    /**
     * Create a new InvalidMacException with the given message.
     * @param message The given message.
     */
    public InvalidSignatureException(String message) {
        super(message);
    }
}
