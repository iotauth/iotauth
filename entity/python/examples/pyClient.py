import argparse
import sys

from iotauth import AuthConnectionError, IoTAuthContext, IoTAuthError, SecureClient


def main():
    parser = argparse.ArgumentParser(description="IoTAuth Python Client Example")
    parser.add_argument("config_path", help="Path to the client config file")
    args = parser.parse_args()

    print("Loading client context...")
    ctx = IoTAuthContext.from_config(args.config_path)

    try:
        # SecureClient handles Auth session key requests and the peer handshake
        with SecureClient(ctx) as client:
            print("Connecting to server...")
            client.connect()
            client.channel.socket.settimeout(1.0)

            messages = [
                b"Hello server",
                b"Hello server - second message",
                b"Hello server - third message",
            ]
            for msg in messages:
                print(f"Sending: {msg.decode('utf-8')}")
                # Encrypt and send data
                client.send(msg)

                # Receive and decrypt the reply
                try:
                    reply = client.recv()
                    print(f"LOG: Received: {reply.decode('utf-8')}")
                except AuthConnectionError as exc:
                    if "timed out" in str(exc).lower():
                        print("No reply received (timeout), continuing...")
                    else:
                        raise

    except IoTAuthError as exc:
        print(f"Client error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
