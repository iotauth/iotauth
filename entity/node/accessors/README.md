# Accessors directory
---
This directory includes *Secure Communication Accessors* as part of SST (Secure Swarm Toolkit), for accessing authorization services provided by local authorization entity, *Auth*.
Secure Communication Accessors are software building blocks that encapsulate cryptographic keys and operations that are used for building trust relationship with other entities and securing network communications.
Therefore, these software building blocks can help IoT developers who are not write IoT applications without worrying about managing cryptography details.
For more general information about accessors, visit [accessors website](http::/accessors.org).

# List of Secure Communication Accessors
---
- **SecureCommClient**: Establishes secure connection with server entities and sends/receives messages to/from servers through the secure connection.
- **SecureCommServer**: Used for Listening to communication requests from secure clients, managing secure communication channels, and exchanging messages with clients.
- **SecurePublisher**: Sends (publishes) secure messages to multiple receivers (subscribers) through MQTT, a publish-subscribe protocol or as UDP broadcasts.
- **SecureSubscriber**: Receives (subscribes) secure messages sent by a sender (publisher) either through MQTT or through UDP broadcasts.
