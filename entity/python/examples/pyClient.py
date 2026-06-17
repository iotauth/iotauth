import os
import sys
from iotauth import IoTAuthContext, SecureClient, IoTAuthError

def main():
    print("Loading client context...")
    config_path = os.path.join(os.path.dirname(__file__), "configs/pyClient.config")
    ctx = IoTAuthContext.from_config(config_path)

    try:
        # SecureClient handles Auth session key requests and the peer handshake
        with SecureClient(ctx) as client:
            print("Connecting to server...")
            client.connect()
            
            messages = [
                b"Hello server",
                b"Hello server - second message",
                b"Hello server - third message"
            ]
            for msg in messages:
                print(f"Sending: {msg.decode('utf-8')}")
                # Encrypt and send data
                client.send(msg)
                
                # Receive and decrypt the reply
                reply = client.recv()
                print(f"LOG: Received: {reply.decode('utf-8')}")
            
    except IoTAuthError as exc:
        print(f"Client error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
