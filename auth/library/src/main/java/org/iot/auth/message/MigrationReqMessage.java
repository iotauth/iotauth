package org.iot.auth.message;

import org.iot.auth.io.Buffer;
import org.iot.auth.io.BufferedString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for a migration request message from an entity.
 * MigrationReq Format
 * {
 *      nonce: /Buffer/, (AUTH_NONCE_SIZE)
 *      replyNonce:    /Buffer/, (AUTH_NONCE_SIZE)
 *      sender: /string/, (senderLen UInt8)
 *  }
 * @author Hokeun Kim
 */
public class MigrationReqMessage extends IoTSPMessage {
    public MigrationReqMessage(MessageType type, Buffer payload) {
        super(type);
        int curIndex = 0;

        this.entityNonce = payload.slice(curIndex, curIndex + ENTITY_NONCE_SIZE);
        curIndex += ENTITY_NONCE_SIZE;

        this.authNonce = payload.slice(curIndex, curIndex + AUTH_NONCE_SIZE);
        curIndex += AUTH_NONCE_SIZE;

        BufferedString bufStr = payload.getBufferedString(curIndex);
        this.entityName = bufStr.getString();
        curIndex += bufStr.length();

        logger.info("Received from entity: " + this.entityName);

    }
    public Buffer getEntityNonce() {
        return entityNonce;
    }
    public Buffer getAuthNonce() {
        return authNonce;
    }
    public String getEntityName() {
        return entityName;
    }

    private Buffer entityNonce;
    private Buffer authNonce;
    private String entityName;

    private static final Logger logger = LoggerFactory.getLogger(MigrationReqMessage.class);
}
