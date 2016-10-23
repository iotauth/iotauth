package org.iot.auth.exception;

/**
 * Exception thrown when trying to use an expired key.
 * @author Hokeun Kim
 */
public class UseOfExpiredKeyException extends Exception {
    /**
     * Create a new UseOfExpiredKeyException with the given message.
     * @param message The given message.
     */
    public UseOfExpiredKeyException(String message) {
        super(message);
    }
}