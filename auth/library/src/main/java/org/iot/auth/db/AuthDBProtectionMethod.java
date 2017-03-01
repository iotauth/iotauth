package org.iot.auth.db;

import java.util.HashMap;
import java.util.Map;

/**
 * @author hokeunkim
 */
public enum AuthDBProtectionMethod {
    DEBUG(0),
    ENCRYPT_CREDENTIALS(1),
    ENCRYPT_ENTIRE_DB(2);

    AuthDBProtectionMethod(int value) {
        this.value = value;
    }
    public int value() {
        return value;
    }
    public static AuthDBProtectionMethod fromValue(int value) {
        return typesByValue.get(value);
    }
    private static final Map<Integer, AuthDBProtectionMethod> typesByValue =
            new HashMap<>();

    static {
        for (AuthDBProtectionMethod type : AuthDBProtectionMethod.values()) {
            typesByValue.put(type.value, type);
        }
    }
    private final int value;
}
