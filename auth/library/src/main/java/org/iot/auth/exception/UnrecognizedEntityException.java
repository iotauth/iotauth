package org.iot.auth.exception;

/**
 * Exception thrown when entity's name is not recognized (not in Auth's database)
 * @author Hokeun Kim
 */
public class UnrecognizedEntityException extends Exception {
    /**
     * Create a new UseOfExpiredKeyException with the given message.
     * @param message The given message.
     */
    public UnrecognizedEntityException(String message) {
        super(message);
    }
}
