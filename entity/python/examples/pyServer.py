import argparse
import sys

from iotauth import IoTAuthContext, IoTAuthError, SecureChannelClosed, SecureServer


def main():
    parser = argparse.ArgumentParser(description="IoTAuth Python Server Example")
    parser.add_argument(
        "-to", "--timeout", type=float, default=60.0, help="Timeout value for server (default 60)"
    )
    parser.add_argument(
        "-m", "--minutes", action="store_true", help="Treat timeout value as minutes"
    )
    parser.add_argument(
        "-s", "--seconds", action="store_true", help="Treat timeout value as seconds (default)"
    )
    parser.add_argument(
        "-n",
        "--max-messages",
        type=int,
        default=0,
        help="Maximum number of messages to process per connection before closing (0 = unlimited)",
    )
    parser.add_argument("config_path", help="Path to the server config file")
    args = parser.parse_args()

    timeout_val = args.timeout
    if args.minutes:  # calcualte time out value in seconds
        timeout_val *= 60.0

    print("Loading server context...")
    ctx = IoTAuthContext.from_config(args.config_path)

    try:
        # SecureServer automatically binds to the host/port in the config
        with SecureServer(ctx, timeout=timeout_val) as server:
            target = ctx.config.targets[0]
            print(f"Listening securely on {target.host}:{target.port}...")

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
                reply_str = (
                    "Hello client" if message_count == 1 else f"Hello client {message_count}"
                )
                channel.send(reply_str.encode("utf-8"))

                if args.max_messages > 0 and message_count >= args.max_messages:
                    print(f"Reached max messages ({args.max_messages}), closing connection.")
                    channel.close()
                    break

                message_count += 1

    except SecureChannelClosed:
        print("Client disconnected.")
    except IoTAuthError as exc:
        print(f"Server error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
