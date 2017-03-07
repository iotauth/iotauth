package org.iot.auth.server;

import org.iot.auth.AuthServer;
import org.iot.auth.io.Buffer;
import org.iot.auth.util.ExceptionToString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Created by hokeunkim on 9/24/16.
 */
public class EntityUdpConnectionHandler extends EntityConnectionHandler {
    /**
     * Constructor for the entity connection handler, to process a connected entity
     * @param server Auth server that this handler is for
     * @param timeout A timeout for the connection with the entity
     */
    public EntityUdpConnectionHandler(AuthServer server, DatagramSocket entitySocket, InetAddress socketAddress,
                                      int socketPort, long timeout, Map<String, Buffer> responseMap, Buffer sessionKeyRequest, Buffer authNonce) {
        super(server);
        this.datagramSocket = entitySocket;
        this.socketAddress = socketAddress;
        this.socketPort = socketPort;
        this.timeOut = timeout;
        this.responseMap = responseMap;
        this.sessionKeyRequest = sessionKeyRequest;
        this.authNonce = authNonce;
        this.isOpen = true;
    }

    /**
     * Run method from the parent class, Thread
     */
    public void run() {
        // Process session key request
        try {
            handleSessionKeyReq(sessionKeyRequest.getRawBytes(), authNonce);
        }
        catch (Exception e) {
            getLogger().error("Exception occurred while handling Auth service!\n {}",
                    ExceptionToString.convertExceptionToStackTrace(e));
            close();
            return;
        }
        close();
    }
    /**
     * Close TCP connection with the entity.
     */
    protected void close() {
        isOpen = false;
    }

    protected Logger getLogger() {
        return logger;
    }

    protected String getRemoteAddress() {
        return socketAddress.toString() + ":" + socketPort;
    }


    protected void writeToSocket(byte[] bytes) throws IOException {
        String addressKey = socketAddress + ":" + socketPort;
        responseMap.put(addressKey, new Buffer(bytes));
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                responseMap.remove(addressKey);
            }
        }, timeOut);
        DatagramPacket packetToSend = new DatagramPacket(bytes, bytes.length, socketAddress, socketPort);
        datagramSocket.send(packetToSend);
    }

    private boolean isOpen() {
        return isOpen;
    }

    private static final Logger logger = LoggerFactory.getLogger(EntityUdpConnectionHandler.class);
    private DatagramSocket datagramSocket;
    private InetAddress socketAddress;
    private int socketPort;
    private long timeOut;
    private boolean isOpen;
    private Map<String, Buffer> responseMap;
    Buffer sessionKeyRequest;
    Buffer authNonce;
}
