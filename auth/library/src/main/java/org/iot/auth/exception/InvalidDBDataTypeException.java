package org.iot.auth.exception;

/**
 * Created by hokeunkim on 2/6/17.
 */
public class InvalidDBDataTypeException extends Exception {
    /**
     * Create a new InvalidDBDataTypeException with the given message.
     * @param message The given message.
     */
    public InvalidDBDataTypeException(String message) {
        super(message);
    }
}

