package org.iot.auth;

import org.json.simple.JSONObject;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Map;

/** Per-Auth JSON Lines history. Never truncates or rotates existing records. */
public final class AuthEventLog {
    private final Path path;
    private final int authID;

    public AuthEventLog(String databaseDir, int authID) throws IOException {
        this.authID = authID;
        path = Paths.get(databaseDir).resolve("events.jsonl");
        Files.createDirectories(path.getParent());
        try (FileChannel channel = open()) {
            // Create an empty log on startup without truncating an existing log.
        }
    }

    private FileChannel open() throws IOException {
        return FileChannel.open(path, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }

    public void append(String event, String outcome, String actor, Map details) throws IOException {
        JSONObject record = new JSONObject();
        record.put("timestamp", Instant.now().toString());
        record.put("authId", authID);
        record.put("event", event);
        record.put("outcome", outcome);
        record.put("actor", actor);
        record.put("details", details);
        ByteBuffer bytes = ByteBuffer.wrap((record.toJSONString() + "\n").getBytes(StandardCharsets.UTF_8));
        // JVM lock also covers multiple logger instances; file lock covers cooperating processes.
        synchronized (AuthEventLog.class) {
            try (FileChannel channel = open(); FileLock lock = channel.lock()) {
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            }
        }
    }
}
