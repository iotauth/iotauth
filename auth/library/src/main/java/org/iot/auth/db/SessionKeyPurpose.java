package org.iot.auth.db;

/**
 * A class for representing purpose field of cached session key table.
 * @author Hokeun Kim
 */
public class SessionKeyPurpose {
    public SessionKeyPurpose(CommunicationTargetType targetType, String target) {
        if (targetType == CommunicationTargetType.TARGET_GROUP) {
            this.targetType = "Group";
        }
        else if (targetType == CommunicationTargetType.PUBLISH_TOPIC ||
                targetType == CommunicationTargetType.SUBSCRIBE_TOPIC) {
            this.targetType = "PubSub";
        }
        else {
            throw new RuntimeException("Unrecognized communication target type for SessionKeyPurpose");
        }
        this.target = target;
    }
    public String toString() {
        return targetType + ":" + target;
    }
    private String targetType;
    private String target;
}
