package org.iot.auth.exception;

/**
 * Exception for when an entity requests session keys on an invalid target.
 * @author Hokeun Kim
 */
public class InvalidSessionKeyTargetException extends Exception {
    /**
     * Create a new InvalidSessionKeyTargetException with the given message.
     * @param message The given message.
     */
    public InvalidSessionKeyTargetException(String message) {
        super(message);
    }
}
