package org.iot.auth.exception;

/**
 * Exception thrown when nonce is not as expected.
 * (e.g., if Auth heartbeat nonce challenge fails in AuthHeartbeatRespMessage)
 *
 * @author Hokeun Kim
 */
public class InvalidNonceException extends Exception {
    /**
     * Create a new InvalidMacException with the given message.
     * @param message The given message.
     */
    public InvalidNonceException(String message) {
        super(message);
    }
}
