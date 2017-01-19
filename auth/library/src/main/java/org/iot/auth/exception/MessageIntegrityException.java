package org.iot.auth.exception;

/**
 * Exception thrown when there is an (unknwon) integrity error.
 * @author Hokeun Kim
 */
public class MessageIntegrityException extends Exception {
    /**
     * Create a new MessageIntegrityException with the given message.
     * @param message The given message.
     */
    public MessageIntegrityException(String message) {
        super(message);
    }
}
