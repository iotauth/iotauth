import os
import sys

from iotauth import IoTAuthContext, IoTAuthError, SecureServer


def main():
    print("Loading server context...")
    config_path = os.path.join(os.path.dirname(__file__), "configs/pyServer.config")
    ctx = IoTAuthContext.from_config(config_path)

    try:
        # SecureServer automatically binds to the host/port in the config
        with SecureServer(ctx) as server:
            print(
                f"Listening securely on {ctx.config.targets[0].host}:{ctx.config.targets[0].port}..."
            )

            # serve_once() accepts a TCP connection and completes auth connection
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
