package org.iot.auth.exception;

/**
 * Exception thrown when there is no distribution key available in Auth DB.
 * @author Hokeun Kim
 */
public class NoAvailableDistributionKeyException extends Exception {
    /**
     * Create a new NoAvailableDistributionKeyException with the given message.
     * @param message The given message.
     */
    public NoAvailableDistributionKeyException(String message) {
        super(message);
    }
}
