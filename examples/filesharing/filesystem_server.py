# from iotauth.entity.python import entity_server
import selectors
import sys
import socket
import os
import types
import secrets
print(os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__)))) +"/entity/python")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__)))) +"/entity/python")
import entity_server

# Setting directories for config, distribution key, and session key
filesystem_manager_dir = {"name" : "", "purpose" : '', "number_key":"", "auth_pubkey_path":"", "privkey_path":"", "auth_ip_address":"", "auth_port_number":"", "port_number":"", "ip_address":"", "network_protocol":"", "pubkey": "", "privkey": ""}
distribution_key = {"abs_validity" : "", "cipher_key" : "", "mac_key" : ""}
session_key = {"sessionkey_id" : "", "abs_validity" : "", "rel_validity" : "", "cipher_key" : "", "mac_key" : ""}

# Load config for file system manager and save public and private key in directory.
entity_server.load_config(sys.argv[1], filesystem_manager_dir)
filesystem_manager_dir["pubkey"] = entity_server.load_pubkey(filesystem_manager_dir["auth_pubkey_path"])
filesystem_manager_dir["privkey"] = entity_server.load_privkey(filesystem_manager_dir["privkey_path"])

node_selector = selectors.DefaultSelector()
def accept_wrapper(sock):
    """Accepts a connection and performs necessary setup.

    Args:
        sock (socket.socket): The listening socket.

    Returns:
        None
    """
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)

    # Setup data for the connection
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE

    # Register the connection with the selector
    node_selector.register(conn, events, data=data)


def service_connection(key, mask):
    """Services an existing connection based on the specified events.

    Args:
        key (selectors.SelectEvent): The key associated with the file object.
        mask (int): The event mask.

    Returns:
        None
    """
    sock = key.fileobj
    data = key.data
    global payload_max_num

    # If it is not a read event, ignore it.
    if not (mask & selectors.EVENT_READ):
        return
        
    # Attempt to receive data from the socket
    recv_data = sock.recv(entity_server.BYTES_NUM)
    # Check for a closed connection
    if not recv_data:
        print(f"Closing connection to {data.addr}")
        node_selector.unregister(sock)
        return

    # Check for a specific indicator in the received data
    if recv_data[0] == entity_server.SKEY_HANDSHAKE_1:
        # Perform session key handshake
        encrypted_buf = entity_server.parse_sessionkey_id(recv_data[2:], filesystem_manager_dir)
        client_sock = entity_server.auth_socket_connect(filesystem_manager_dir)
        nonce_entity = secrets.token_bytes(entity_server.NONCE_SIZE)

        while True:
            # Check if we have the expected session key
            if session_key["sessionkey_id"] == recv_data[2:2+entity_server.NONCE_SIZE]:
                print("We have the session key.")
                # Decrypt the buffer using the session key
                dec_buf = entity_server.symmetric_decrypt_hmac(session_key, encrypted_buf[:32], encrypted_buf[32:])
                print(dec_buf)
                # Close the client socket and exit the loop
                client_sock.close()
                break
            # Receive data from the authentication server
            recv_data_from_auth = client_sock.recv(entity_server.BYTES_NUM)
            # Continue the loop if no data received
            if len(recv_data_from_auth) == 0:
                continue
            # Process the received data to get the session key
            entity_server.get_session_key(recv_data_from_auth, filesystem_manager_dir, client_sock, distribution_key, session_key, nonce_entity)

host, port = filesystem_manager_dir["ip_address"], int(filesystem_manager_dir["port_number"])

manager_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
manager_socket.bind((host, port))
manager_socket.listen()
print(f"Listening on {(host, port)}")
manager_socket.setblocking(False)
node_selector.register(manager_socket, selectors.EVENT_READ, data=None)

try:
    while True:
        events = node_selector.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    manager_socket.close()
    node_selector.close()
    print("Finished")
