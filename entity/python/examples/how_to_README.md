# Building a Python IoTAuth Client and Server

This guide will walk you through creating a simple echo server and client using the Python IoTAuth API we just built. We'll reuse the existing demo credentials provided in the repository.

All files in this tutorial will be created in a new `entity/python/examples` directory.

> [!TIP]
> Before you begin, ensure you have the required `cryptography` dependency installed in your virtual environment:
> ```bash
> entity/python/.venv/bin/python -m pip install cryptography
> ```

---

## Step 1: Create the directory

Open your terminal and create a folder to hold our examples:

```bash
mkdir -p entity/python/examples
cd entity/python/examples
```

## Step 2: Create the configurations

IoTAuth relies on configuration files to know who the entity is and where its credentials live. We'll use the existing demo keys from `../../credentials/keys` and `../../auth_certs`.

Create a file named `server.config`:
```properties
entityInfo.name=net1.server
entityInfo.purpose={"group":"Servers"}
entityInfo.number_key=3
authInfo.id=101
sessionKey.encryptionMode=AES_128_CBC
# Path to the Auth public key
authInfo.pubkey.path=../../../auth_certs/Auth101EntityCert.pem
# Path to the server's private key
entityInfo.privkey.path=../../../credentials/keys/net1/Net1.ServerKey.pem
auth.ip.address=127.0.0.1
auth.port.number=21900
entity.server.ip.address=127.0.0.1
entity.server.port.number=21100
network.protocol=TCP
```

Create a file named `client.config`:
```properties
entityInfo.name=net1.client
entityInfo.purpose={"group":"Servers"}
entityInfo.number_key=3
authInfo.id=101
sessionKey.encryptionMode=AES_128_CBC
# Path to the Auth public key
authInfo.pubkey.path=../../../auth_certs/Auth101EntityCert.pem
# Path to the client's private key
entityInfo.privkey.path=../../../credentials/keys/net1/Net1.ClientKey.pem
auth.ip.address=127.0.0.1
auth.port.number=21900
entity.server.ip.address=127.0.0.1
entity.server.port.number=21100
network.protocol=TCP
```

## Step 3: Write the Server Script

Create `server.py`. The server will use `SecureServer` to listen for connections, perform the secure handshake, and bounce any received messages back to the client.

```python
import sys
from iotauth import IoTAuthContext, SecureServer, IoTAuthError

def main():
    print("Loading server context...")
    ctx = IoTAuthContext.from_config("server.config")

    try:
        # SecureServer automatically binds to the host/port in the config
        with SecureServer(ctx) as server:
            print(f"Listening securely on {ctx.config.targets[0].host}:{ctx.config.targets[0].port}...")
            
            # serve_once() accepts a TCP connection and completes the secure handshake
            channel = server.serve_once()
            print("Secure connection established!")
            
            while True:
                # Wait for encrypted data from the client
                data = channel.recv()
                if not data:
                    print("Client disconnected.")
                    break
                    
                print(f"Received secure message: {data.decode('utf-8')}")
                
                # Echo the data back securely
                reply = b"Server Echo: " + data
                channel.send(reply)
                
    except IoTAuthError as exc:
        print(f"Server error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Step 4: Write the Client Script

Create `client.py`. The client will use `SecureClient` to automatically fetch session keys from Auth (if needed), securely connect to the server, and send a message.

```python
import sys
from iotauth import IoTAuthContext, SecureClient, IoTAuthError

def main():
    print("Loading client context...")
    ctx = IoTAuthContext.from_config("client.config")

    try:
        # SecureClient handles Auth session key requests and the peer handshake
        with SecureClient(ctx) as client:
            print("Connecting to server...")
            client.connect()
            
            message = b"Hello from the new Python API!"
            print(f"Sending: {message.decode('utf-8')}")
            
            # Encrypt and send data
            client.send(message)
            
            # Receive and decrypt the reply
            reply = client.recv()
            print(f"Received reply: {reply.decode('utf-8')}")
            
    except IoTAuthError as exc:
        print(f"Client error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Step 5: Run the Demo

To run these scripts, you need three terminal windows (all from the repository root `OPT_project/iotauth`).

> [!WARNING]
> The Java Auth server must be running first because both the Python client and server will need to communicate with it to validate session keys.

**Terminal 1 (Auth Server):**
Start the Java Auth server (refer to existing project instructions if you need to build it first). 
```bash
cd auth
java -jar target/iotauth-1.0-SNAPSHOT-jar-with-dependencies.jar properties/exampleAuth101.properties
```
*(Note: Your auth jar name might vary slightly depending on your build).*

**Terminal 2 (Python Server):**
Start the Python entity server. It will wait for the client to connect.
```bash
PYTHONPATH=entity/python entity/python/.venv/bin/python entity/python/examples/server.py
```

**Terminal 3 (Python Client):**
Run the client. It will fetch a session key from the Auth server, securely connect to your Python server, and print the echo response!
```bash
PYTHONPATH=entity/python entity/python/.venv/bin/python entity/python/examples/client.py
```
