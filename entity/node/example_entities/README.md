# Node.js Example Entities

This directory contains example Node.js entities that use SST (Secure Swarm Toolkit) to communicate with an Auth and with other entities.  

To use these entities, refer to [iotauth/examples/README.md](https://github.com/iotauth/iotauth/tree/main/examples)
```
node client.js configs/net1/client.config
```

For automated end-to-end tests that start Auth, a server, and a client in a single command, see [`examples/scripts/README.md`](../../../examples/scripts/README.md).

## Available entities
### 1. server.js
A general-purpose secure server that listens for incoming client connections on the port specified in its config file.  Prints received data to stdout.  Used as the server in [`c_client_node_server_test.sh`](../../../examples/scripts/c_client_node_server_test.sh) and [`node_client_node_server_test.sh`](../../../examples/scripts/node_client_node_server_test.sh).
```
node server.js configs/net1/server.config
```

### 2. client.js
A general-purpose interactive secure client.

### 3. autoClient.js
A non-interactive client that automatically connects to the server specified in its config, sends `"data2"` and then `"data1"` (5 seconds apart), and reconnects every ~10 seconds.  Used as the client in [`node_client_c_server_test.sh`](../../../examples/scripts/node_client_c_server_test.sh) and [`node_client_node_server_test.sh`](../../../examples/scripts/node_client_node_server_test.sh).
```
node autoClient.js configs/net1/client.config
```

### 4. user.js
Represents a human user entity capable of delegating access.
#### Features
- Loads `configs/net1/user.config` by default.
- Provides command:
    - delegateAccess `<high|medium|low>`
    - Requests a session-key ID that can be granted to another entity (an agent).
#### How to use
```
node user.js configs/net1/user.config
delegateAccess high
```

### 5. agent.js
Represents an agent entity that acts on behalf of a user using delegated access.
#### Features
- Loads `configs/net1/highTrustAgent.config` by default.
- Retrieve delegated session keys via `getSessionKeysForGrantAccess(keyId)`.
#### How to use
```
node agent.js configs/net1/highTrustAgent.config keyId 10100000
```

### 6. website.js
Represents a website service entity that receives session key Id from an agent.
#### Features
- Loads `configs/net1/website.config` by default.
- Retrieve delegated session keys via `getSessionKeysForGrantAccess(keyId)`.
- It will return the session key with the group of the session key owner who submitted the session-key ID (e.g., `HighTrustAgents`, `MediumTrustAgents`, `LowTrustAgents`). 
This allows the website to confirm which agent group issued the delegation used for the connection.
#### How to use
```
node website.js configs/net1/website.config keyId 10100000
```

### 7. autoPrivilege.js
Automatically performs batch privilege operations such as `DelegationGrant` or `DelegationRevoke` using predefined test cases from a JSON file (default: `privilege.json`).
### Features
- Loads privilege test cases from `privileges.json` by default.
- Supports both:
  - `DelegationGrant`
  - `DelegationRevoke`
- Measures:
  - per-request latency 
  - total execution time 
  - success/failure statistics
#### Input Format
The script reads test configurations from a JSON file:
```
{
  "defaultValidity": "1*day",
  "defaultTimeoutMs": 10000,
  "tests": [
    {
      "nodeConfig": "configs/net1/node0.config",
      "subject": "Node1",
      "object": "ResourceA"
    }
  ]
}
```

`privileges.json` contains a small set of example privilege operations for simple testing.

#### How to use
```
# It will use privileges.json as default.
node autoPrivilege.js DelegationGrant 
node autoPrivilege.js DelegationRevoke 

# Use a custom JSON test configuration file.
node autoPrivilege.js DelegationGrant your_custom_test.json
```

The file dbsec_test.json contains the automated privilege test configuration used for the DBsec paper experiments.
```
# Run the DBsec paper experiment configuration.
node autoPrivilege.js DelegationGrant dbsec_test.json
node autoPrivilege.js DelegationRevoke dbsec_test.json
```

#### Example Output
```
[PASS] configs/net1/node1.config | Node3 -> ResourceA | 101.543 ms

========== SUMMARY ==========
Total tests   : 3
Success       : 3
Fail          : 0
Success rate  : 100.00%
Total latency : 307.252 ms
Avg latency   : 102.417 ms
End-to-end    : 312.987 ms
```
