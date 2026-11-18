package org.iot.auth;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;

public class AuthEventLogTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();

    @Test public void timestampFirstAndHistorySurvivesRestart() throws Exception {
        Path dir = temp.newFolder("auth101").toPath();
        Path log = dir.resolve("authlog.txt");
        Files.write(log, "existing record\n".getBytes(StandardCharsets.UTF_8));
        try (AuthEventLog writer = new AuthEventLog(dir.toString(), 101)) {
            writer.append("ACCESS", "SUCCESS", "robot\n1", Collections.singletonMap("target", "item\nA"));
        }
        byte[] before = Files.readAllBytes(log);
        try (AuthEventLog writer = new AuthEventLog(dir.toString(), 101)) {
            writer.append("DELEGATION", "SUCCESS", "supervisor", Collections.emptyMap());
            writer.append("REVOCATION", "REJECTED", "supervisor", Collections.emptyMap());
        }
        byte[] after = Files.readAllBytes(log);
        assertArrayEquals(before, Arrays.copyOf(after, before.length));
        List<String> lines = Files.readAllLines(log, StandardCharsets.UTF_8);
        assertEquals(4, lines.size());
        assertEquals("existing record", lines.get(0));
        String access = lines.get(1);
        assertTrue(access.startsWith("["));
        Instant.parse(access.substring(1, access.indexOf(']')));
        assertTrue(access.contains("] Auth101 ACCESS SUCCESS actor=\"robot\\n1\""));
        assertTrue(access.contains("item\\nA"));
        assertTrue(lines.get(2).contains("DELEGATION SUCCESS"));
        assertTrue(lines.get(3).contains("REVOCATION REJECTED"));
        assertFalse(Files.exists(dir.resolve("events.jsonl")));
    }

    @Test public void concurrentWritesStayCompleteAndAuthsAreSeparate() throws Exception {
        Path first = temp.newFolder("auth101").toPath();
        Path second = temp.newFolder("auth102").toPath();
        try (AuthEventLog one = new AuthEventLog(first.toString(), 101);
             AuthEventLog same = new AuthEventLog(first.toString(), 101);
             AuthEventLog two = new AuthEventLog(second.toString(), 102)) {
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Future<?>> futures = new ArrayList<>();
                for (int i = 0; i < 100; i++) {
                    final int id = i;
                    futures.add(pool.submit(() -> {
                        (id % 2 == 0 ? one : same).append("ACCESS", "SUCCESS", "actor" + id, Collections.emptyMap());
                        return null;
                    }));
                }
                for (Future<?> f : futures) f.get();
            } finally { pool.shutdownNow(); }
            two.append("ACCESS", "FAILED", "other", Collections.emptyMap());
        }
        List<String> lines = Files.readAllLines(first.resolve("authlog.txt"));
        assertEquals(100, lines.size());
        Set<String> actors = new HashSet<>();
        for (String line : lines) {
            assertTrue(line.startsWith("["));
            assertTrue(line.endsWith("details={}"));
            actors.add(line.substring(line.indexOf("actor=")));
        }
        assertEquals(100, actors.size());
        List<String> other = Files.readAllLines(second.resolve("authlog.txt"));
        assertEquals(1, other.size());
        assertTrue(other.get(0).contains("Auth102 ACCESS FAILED"));
    }
}
