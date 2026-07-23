import argparse
import sys

from iotauth import IoTAuthContext, IoTAuthError, SecureChannelClosed, SecureServer


def main():
    parser = argparse.ArgumentParser(description="IoTAuth Python Server Example")
    parser.add_argument(
        "--accept-timeout",
        type=float,
        default=None,
        help="Seconds to wait for a client connection (default: wait indefinitely)",
    )
    parser.add_argument(
        "--handshake-timeout",
        type=float,
        default=5.0,
        help="Seconds to complete an accepted client's handshake (default: 5)",
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

    print("Loading server context...")
    ctx = IoTAuthContext.from_config(args.config_path)

    try:
        # SecureServer automatically binds to the host/port in the config
        with SecureServer(
            ctx,
            accept_timeout=args.accept_timeout,
            handshake_timeout=args.handshake_timeout,
        ) as server:
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

                # Send response back securely
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
