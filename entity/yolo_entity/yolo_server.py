import argparse
import socket
import pathlib
import os

try:
    from iotauth.context import IoTAuthContext
except ImportError:
    IoTAuthContext = None
    print("Warning: iotauth package not found in current environment.")

def main():
    parser = argparse.ArgumentParser(description="YOLO Python IoT Auth Server")
    parser.add_argument('--config', type=str, help='Path to the entity .config file', required=True)
    parser.add_argument('--port', type=int, default=21100, help='Port to listen on')
    args = parser.parse_args()

    if IoTAuthContext is None:
        print("Cannot start server: IoTAuth package not available.")
        return

    abs_config_path = pathlib.Path(args.config).resolve()
    original_cwd = os.getcwd()
    
    expected_anchor = abs_config_path.parent.parent.parent
    if expected_anchor.name == 'example_entities':
        print(f" -> Automatically adjusting CWD to '{expected_anchor.name}' for path resolution.")
        os.chdir(expected_anchor)
        
    try:
        ctx = IoTAuthContext.from_config(str(abs_config_path))
    finally:
        os.chdir(original_cwd)

    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv_sock.bind(('0.0.0.0', args.port))
    serv_sock.listen(5)

    print(f"Server listening securely on port {args.port}...")

    try:
        while True:
            client_sock, addr = serv_sock.accept()
            print(f"\n[+] Accepted TCP connection from {addr}")
            
            try:
                # Perform secure handshake using IoTAuth
                secure_channel = ctx.accept_secure(client_sock)
                
                # The accept_secure method sets a 5-second timeout for the handshake.
                # We need to disable the timeout so we can wait indefinitely for messages!
                secure_channel.socket.settimeout(None)
                
                print("[+] Secure handshake successful. Waiting for messages...")
                
                while True:
                    try:
                        msg = secure_channel.recv()
                        print(f" -> Received secure message: {msg.decode('utf-8')}")
                    except Exception as e:
                        print(f"[-] Secure channel closed or error: {e}")
                        break
            except Exception as e:
                print(f"[-] Secure handshake failed: {e}")
            finally:
                try:
                    client_sock.close()
                except Exception:
                    pass
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully.")
    finally:
        serv_sock.close()

if __name__ == "__main__":
    main()
