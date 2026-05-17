# Node.js Example Entities

This directory contains example Node.js entities that use SST (Secure Swarm Toolkit) to communicate with an Auth and with other entities.  

To use these entities, refer to [iotauth/examples/README.md](https://github.com/iotauth/iotauth/tree/master/examples)
```
node client.js configs/net1/client.config
```

## Available entities
### 1. client.js
A general-purpose interactive secure client.

### 2. user.js
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

### 3. agent.js
Represents an agent entity that acts on behalf of a user using delegated access.
#### Features
- Loads `configs/net1/highTrustAgent.config` by default.
- Retrieve delegated session keys via `getSessionKeysForGrantAccess(keyId)`.
#### How to use
```
node agent.js configs/net1/highTrustAgent.config keyId 10100000
```

### 4. website.js
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

### 5. autoPrivilege.js
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
#### How to use
```
# It will use privileges.json as default.
node autoPrivilege.js DelegationGrant   
node autoPrivilege.js DelegationRevoke  
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
