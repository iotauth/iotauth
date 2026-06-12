# SST Integration Test Scripts

Each script in this directory builds, configures, and runs one combination of client and server entity implementations, then verifies the expected output.  All scripts require Auth101 to be running (started automatically) and use ports **21900/21901** (Auth server) and **21100** (entity server).

---

## Quick reference

| Script | Client | Server | Build deps |
|--------|--------|--------|------------|
| `c_client_node_server_test.sh` | C `entity_client` | Node `server.js` | mvn, cmake, make, node, npm |
| `c_client_c_server_test.sh` | C `entity_client` | C `entity_server` | mvn, cmake, make |
| `node_client_c_server_test.sh` | Node `autoClient.js` | C `entity_server` | mvn, cmake, make, node, npm |
| `node_client_node_server_test.sh` | Node `autoClient.js` | Node `server.js` | mvn, node, npm |

---

## Common options

All four scripts accept the same flags:

```
--password <pw>          Auth password (default: 1234)
--client-timeout <sec>   Max wait for client to complete (default: 45)
--service-timeout <sec>  Max wait for services to become ready (default: 45)
--no-build               Skip Maven / CMake build
--no-setup               Skip cleanAll.sh / generateAll.sh
--no-verify              Run without checking output
--keep-logs              Keep log files after the test finishes
--stop-existing          Kill any process already listening on 21900/21901/21100
--tmux                   Open Auth, server, and client in a 3-pane tmux session
-h, --help               Show usage
```

---

## Script details

### `c_client_node_server_test.sh` — C client → Node server

**Entities**
- Client: `entity/c/examples/server_client_example/build/entity_client` (config: `c_client.config`)
- Server: `entity/node/example_entities/server.js` (config: `configs/net1/server.config`)

**Message flow**

The C client makes two sequential connections to the Node server.  Only the client sends application data; the server receives and logs it.

| Connection | Client sends |
|------------|-------------|
| 1st | `"Hello server"`, then `"Hello server - second message"` |
| 2nd | `"Hello server 2"`, then `"Hello server 2 - second message"` |

**Termination**  
The C client exits after its second connection completes.  The script waits for the client process to exit naturally (up to `--client-timeout`), then stops Auth and the Node server.

**Readiness detection**  
The Node server is considered ready when its log contains `Handler: listening on port` (log-based).

**Verified output (Node server log)**
```
data: Hello server
data: Hello server - second message
data: Hello server 2
data: Hello server 2 - second message
```

---

### `c_client_c_server_test.sh` — C client → C server

**Entities**
- Client: `entity/c/examples/server_client_example/build/entity_client` (config: `c_client.config`)
- Server: `entity/c/examples/server_client_example/build/entity_server` (config: `c_server.config`)

**Message flow**

Both sides send messages on each connection.  The C client spawns a background receive thread per connection to read server replies.

| Connection | Client sends | Server replies |
|------------|-------------|----------------|
| 1st | `"Hello server"`, then `"Hello server - second message"` | `"Hello client"`, then `"Hello client - second message"` |
| 2nd | `"Hello server 2"`, then `"Hello server 2 - second message"` | `"Hello client 2"`, then `"Hello client 2 - second message"` |

**Termination**  
The C client exits after its second connection.  The script waits for the client process to exit naturally, then kills the C server and Auth.

**Readiness detection**  
The C server produces no structured startup log, so readiness is detected by polling port 21100 until it is open (port-based).

**Verified output**
```
# C server log
LOG: Received: Hello server
LOG: Received: Hello server - second message
LOG: Received: Hello server 2
LOG: Received: Hello server 2 - second message

# C client log
LOG: Received: Hello client
LOG: Received: Hello client 2
```

---

### `node_client_c_server_test.sh` — Node client → C server

**Entities**
- Client: `entity/node/example_entities/autoClient.js` (config: `configs/net1/client.config`)
- Server: `entity/c/examples/server_client_example/build/entity_server` (config: `c_server.config`)

**Message flow**

`autoClient.js` uses an automatic reconnect loop (`autoConnect()`): it opens a connection, sends `"data2"`, waits ~5 seconds, sends `"data1"`, then reconnects again every ~10 seconds.  The C server is coded to `accept()` exactly two connections and then exit, so the two connections provided by the first two loops of `autoClient` satisfy it naturally — no forced kill of the server is needed.

The C server replies with `"Hello client"` on each connection, which `autoClient` receives and logs.

| Connection | Client sends | Server replies |
|------------|-------------|----------------|
| 1st | `"data2"`, then `"data1"` | `"Hello client"` |
| 2nd | `"data2"`, then `"data1"` | `"Hello client"` |

**Termination**  
The script waits for the C server process to exit on its own (after both connections).  `autoClient` is then killed.

**Readiness detection**  
Port-based: waits until port 21100 is open (the C server emits no structured log line on startup).

**Verified output**
```
# C server log
LOG: Received: data2
Finished first communication

# Node client log
Hello client
```

---

### `node_client_node_server_test.sh` — Node client → Node server

**Entities**
- Client: `entity/node/example_entities/autoClient.js` (config: `configs/net1/client.config`)
- Server: `entity/node/example_entities/server.js` (config: `configs/net1/server.config`)

**Message flow**

Same `autoClient` loop as above.  The Node server stays alive indefinitely; it does not exit after a fixed number of connections.  The script stops as soon as the server log shows that `"data1"` was received (the second message of the first connection), confirming a full round-trip.

| Connection | Client sends |
|------------|-------------|
| 1st (and onward) | `"data2"`, then `"data1"` |

The Node server does not send application data back to the client; only the client sends messages.

**Termination**  
The script kills `autoClient` once `data: data1` appears in the server log, then stops the server and Auth.

**Readiness detection**  
Log-based: waits for `Handler: listening on port` in the server log.

**Verified output (Node server log)**
```
Handler: socketID:
data: data2
data: data1
```
