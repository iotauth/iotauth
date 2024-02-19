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
file_manager_dict = {"name" : "", "purpose" : '', "number_key":"", "auth_pubkey_path":"", "privkey_path":"", "auth_ip_address":"", "auth_port_number":"", "port_number":"", "ip_address":"", "network_protocol":"", "pubkey": "", "privkey": ""}
distribution_key = {"abs_validity" : "", "cipher_key" : "", "mac_key" : ""}
session_key = {"sessionkey_id" : "", "abs_validity" : "", "rel_validity" : "", "cipher_key" : "", "mac_key" : ""}

# Setting directories for managing information of the file
file_center = {"name":[] , "keyid" : [], "hash_value" : []}
log_center = {"name":[] , "keyid" : [], "hash_value" : []}
download_list = []

# Load config for file system manager and save public and private key in directory.
entity_server.load_config(sys.argv[1], file_manager_dict)
file_manager_dict["pubkey"] = entity_server.load_pubkey(file_manager_dict["auth_pubkey_path"])
file_manager_dict["privkey"] = entity_server.load_privkey(file_manager_dict["privkey_path"])

sequential_num = 0

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
    global payload_max_num, sequential_num

    # If it is not a read event, ignore it.
    if not (mask & selectors.EVENT_READ):
        return
        
    # Attempt to receive data from the socket
    recv_data = sock.recv(entity_server.READ_BYTES_NUM)
    # Check for a closed connection
    if not recv_data:
        print(f"Closing connection to {data.addr}")
        node_selector.unregister(sock)
        return
    msg_type, received_message = entity_server.parse_received_message(recv_data)
    # Check for a specific indicator in the received data
    if msg_type == entity_server.SKEY_HANDSHAKE_1:
        print("received session key handshake1!\n")
        # Perform session key handshake
        encrypted_buf = entity_server.parse_sessionkey_id(received_message, file_manager_dict)
        client_sock = entity_server.auth_socket_connect(file_manager_dict)
        nonce_auth = secrets.token_bytes(entity_server.NONCE_SIZE)

        while True:
            # Check if we have the expected session key
            if session_key["sessionkey_id"] == received_message[:entity_server.NONCE_SIZE]:
                print("We have the session key...!!")
                client_sock.close()
                # Decrypt the buffer using the session key
                dec_buf = entity_server.symmetric_decrypt_hmac(session_key, encrypted_buf[:len(encrypted_buf)-entity_server.MAC_KEY_SIZE], encrypted_buf[len(encrypted_buf)-entity_server.MAC_KEY_SIZE:])
                # Handshake2
                nonce_entity = dec_buf[1:]
                nonce_server = secrets.token_bytes(entity_server.NONCE_SIZE)
                print("nonce_server: ")
                print(nonce_server)
                serialized_buffer = entity_server.serialize_handshake(nonce_server, nonce_entity)
                print("serialized_buffer: ")
                print(serialized_buffer)
                enc_buffer = entity_server.symmetric_encrypt_hmac(session_key, serialized_buffer)
                total_buffer = entity_server.make_sender_buffer(enc_buffer, entity_server.SKEY_HANDSHAKE_2)
                sock.send(bytes(total_buffer))
                # Close the client socket and exit the loop
                break
            # Receive data from the authentication server
            recv_data_from_auth = client_sock.recv(entity_server.READ_BYTES_NUM)
            # Continue the loop if no data received
            if len(recv_data_from_auth) == 0:
                continue
            # Process the received data to get the session key
            entity_server.get_session_key(recv_data_from_auth, file_manager_dict, client_sock, distribution_key, session_key, nonce_auth)

    if msg_type == entity_server.SKEY_HANDSHAKE_3:
        dec_buf = entity_server.symmetric_decrypt_hmac(session_key, received_message[:len(received_message)-entity_server.MAC_KEY_SIZE], received_message[len(received_message)-entity_server.MAC_KEY_SIZE:])
        print("received session key handshake3!\n")
        print(dec_buf)
    if msg_type == entity_server.SECURE_COMM_MSG:
        print("Received secure message!!")
        dec_buf = entity_server.symmetric_decrypt_hmac(session_key, received_message[:len(received_message)-entity_server.MAC_KEY_SIZE], received_message[len(received_message)-entity_server.MAC_KEY_SIZE:])
        seq_num = entity_server.read_int_from_buf(dec_buf, entity_server.SEQ_NUM_SIZE)
        print("Received sequential number:", seq_num)
        print("Decrypted message:", dec_buf[entity_server.SEQ_NUM_SIZE:])
        if dec_buf[entity_server.SEQ_NUM_SIZE] == entity_server.DATA_UPLOAD_REQ:
            entity_server.save_info_for_file(dec_buf[entity_server.SEQ_NUM_SIZE:], file_center)
            print(file_center)
        elif dec_buf[entity_server.SEQ_NUM_SIZE] == entity_server.DATA_DOWNLOAD_REQ:
                print(dec_buf[:entity_server.SEQ_NUM_SIZE - 1])
                # dec_buf[entity_server.SEQ_NUM_SIZE - 1] += 
                
                seq_buffer = entity_server.write_in_n_bytes(sequential_num, entity_server.SEQ_NUM_SIZE)
                message = entity_server.concat_data(dec_buf[entity_server.SEQ_NUM_SIZE:], file_center, log_center, download_list)
                total_message = bytearray(entity_server.SEQ_NUM_SIZE + len(message))
                total_message[:entity_server.SEQ_NUM_SIZE - 1] = seq_buffer
                total_message[entity_server.SEQ_NUM_SIZE:] = message
                print(total_message)
                enc_buffer = entity_server.symmetric_encrypt_hmac(session_key, total_message)
                total_buffer = entity_server.make_sender_buffer(enc_buffer, entity_server.SECURE_COMM_MSG)
                sock.send(bytes(total_buffer))
                sequential_num += 1

host, port = file_manager_dict["ip_address"], int(file_manager_dict["port_number"])

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
