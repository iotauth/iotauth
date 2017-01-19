package org.iot.auth.exception;

/**
 * Exception thrown when there session keys more than max session keys per request are requested by an entity.
 * @author Hokeun Kim
 */
public class TooManySessionKeysRequestedException extends Exception {
    /**
     * Create a new TooManySessionKeysRequestedException with the given message.
     * @param message The given message.
     */
    public TooManySessionKeysRequestedException(String message) {
        super(message);
    }
}
