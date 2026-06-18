import argparse
import os
import sys

from iotauth import IoTAuthContext, IoTAuthError, SecureServer, SecureChannelClosed


def main():
    parser = argparse.ArgumentParser(description="IoTAuth Python Server Example")
    parser.add_argument("-to", "--timeout", type=float, default=60.0, help="Timeout value for server (default 60)")
    parser.add_argument("-m", "--minutes", action="store_true", help="Treat timeout value as minutes")
    parser.add_argument("-s", "--seconds", action="store_true", help="Treat timeout value as seconds (default)")
    args = parser.parse_args()

    timeout_val = args.timeout
    if args.minutes:
        timeout_val *= 60.0

    print("Loading server context...")
    config_path = os.path.join(os.path.dirname(__file__), "configs/pyServer.config")
    ctx = IoTAuthContext.from_config(config_path)

    try:
        # SecureServer automatically binds to the host/port in the config
        with SecureServer(ctx, timeout=timeout_val) as server:
            print(
                f"Listening securely on {ctx.config.targets[0].host}:{ctx.config.targets[0].port}..."
            )

            # serve_once() accepts a TCP connection and completes auth connection
            channel = server.serve_once()
            print("Secure connection established!")

            message_count = 1
            while True:
                # Wait for encrypted data from the client
                data = channel.recv()
                if not data:
                    print("Client disconnected.")
                    break

                print(f"LOG: Received: {data.decode('utf-8')}")

                # Echo the data back securely
                reply_str = "Hello client" if message_count == 1 else f"Hello client {message_count}"
                channel.send(reply_str.encode('utf-8'))
                message_count += 1

    except SecureChannelClosed:
        print("Client disconnected.")
    except IoTAuthError as exc:
        print(f"Server error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
