package org.iot.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.FileAppender;
import org.json.simple.JSONValue;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/** Per-Auth, timestamp-first event history, written through a Logback logger. */
public final class AuthEventLog implements Closeable {
    private final int authID;
    private final LoggerContext context;
    private final Logger logger;

    public AuthEventLog(String databaseDir, int authID) throws IOException {
        this.authID = authID;
        Path path = Paths.get(databaseDir).resolve("authlog.txt");
        // An isolated context avoids routing audit events through console/rolling appenders
        // or depending on which SLF4J provider the server's assembled JAR selects.
        context = new LoggerContext();
        context.setName("auth-events-" + authID);
        context.start();

        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setCharset(StandardCharsets.UTF_8);
        encoder.setPattern("[%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX,UTC}] %msg%n");
        encoder.start();

        FileAppender<ILoggingEvent> appender = new FileAppender<>();
        appender.setContext(context);
        appender.setName("AUTH_EVENTS");
        appender.setFile(path.toString());
        appender.setAppend(true);
        appender.setPrudent(true); // Lock writes if cooperating Auth processes share the file.
        appender.setImmediateFlush(true);
        appender.setEncoder(encoder);
        appender.start();
        if (!appender.isStarted()) {
            encoder.stop();
            context.stop();
            throw new IOException("Cannot open Auth event log: " + path);
        }

        logger = context.getLogger("auth.events");
        logger.setAdditive(false);
        logger.setLevel(Level.INFO);
        logger.addAppender(appender);
    }

    public void append(String event, String outcome, String actor, Map details) throws IOException {
        // JSON escaping keeps untrusted actor/details text within a single log line.
        synchronized (AuthEventLog.class) {
            logger.info("Auth{} {} {} actor={} details={}", authID,
                    singleLine(event), singleLine(outcome), JSONValue.toJSONString(actor),
                    JSONValue.toJSONString(details));
        }
    }

    private static String singleLine(String value) {
        return value == null ? "null" : value.replace("\r", "\\r").replace("\n", "\\n");
    }

    @Override
    public void close() {
        context.stop();
    }
}
