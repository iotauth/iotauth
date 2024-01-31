# from iotauth.entity.python import entity_server
import selectors
import sys
import socket
import os
import types
print(os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__)))) +"/entity/python")
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__)))) +"/entity/python")
import entity_server


filesystemManager_dir = {"name" : "", "purpose" : '', "number_key":"", "auth_pubkey_path":"", "privkey_path":"", "auth_ip_address":"", "auth_port_number":"", "port_number":"", "ip_address":"", "network_protocol":""}

distribution_key = {"abs_validity" : "", "cipher_key" : "", "mac_key" : ""}
session_key = {"sessionkey_id" : "", "abs_validity" : "", "rel_validity" : "", "cipher_key" : "", "mac_key" : ""}


entity_server.load_config(sys.argv[1], filesystemManager_dir)
sel = selectors.DefaultSelector()

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    global payload_max_num
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(entity_server.BYTES_NUM)  # Should be ready to read
        if not recv_data:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
        else:
            if recv_data[0] == entity_server.SKEY_HANDSHAKE_1:
                encrypted_buf = entity_server.parse_sessionkey_id(recv_data[2:], filesystemManager_dir)
                client_sock = entity_server.auth_socket_connect(filesystemManager_dir)
                public_key = entity_server.load_pubkey(filesystemManager_dir["auth_pubkey_path"])
                private_key = entity_server.load_privkey(filesystemManager_dir["privkey_path"])
                while(1):
                    recv_data_from_auth = client_sock.recv(entity_server.BYTES_NUM)
                    if len(recv_data_from_auth) == 0:
                        continue
                    msg_type = recv_data_from_auth[0]
                    length, length_buf = entity_server.var_length_int_to_num(recv_data_from_auth[1:])
                    if msg_type == entity_server.AUTH_HELLO:
                        nonce_auth = recv_data_from_auth[entity_server.AUTH_ID+1+length_buf:]
                        serialize_message, nonce_entity = entity_server.serialize_message_for_auth(filesystemManager_dir, nonce_auth)
                        
                        ciphertext = entity_server.asymmetric_encrypt(serialize_message, public_key)
                        signature = entity_server.sha256_sign(ciphertext, private_key)
                        
                        total_buffer = entity_server.send_sessionkey_request(ciphertext, signature)
                        client_sock.send(bytes(total_buffer))

                    elif msg_type == entity_server.SESSION_KEY_RESP_WITH_DIST_KEY:
                        recv_data = recv_data_from_auth[1+length_buf:]
                        entity_server.parse_distributionkey(recv_data, public_key, private_key, distribution_key)
                        
                        encrytped_sessionkey = recv_data[entity_server.RSA_KEY_SIZE*2:]
                        
                        encrypted_buffer = encrytped_sessionkey[:len(encrytped_sessionkey)-len(distribution_key["mac_key"])]
                        received_tag = encrytped_sessionkey[len(encrytped_sessionkey)-len(distribution_key["mac_key"]):]

                        decrypted_buf = entity_server.symmetric_decrypt_hmac(distribution_key, encrypted_buffer, received_tag)
                        
                        recv_nonce_entity = decrypted_buf[:entity_server.NONCE_SIZE]
                        if nonce_entity != recv_nonce_entity:
                            print("Failed for communication with Auth")
                            exit()
                        else:    
                            print("Success for communication with Auth")

                        crypto_buf, crypto_buf_length = entity_server.var_length_int_to_num(decrypted_buf[entity_server.NONCE_SIZE:])
                        crypto_info = decrypted_buf[entity_server.NONCE_SIZE+crypto_buf_length:entity_server.NONCE_SIZE+crypto_buf_length+crypto_buf]
                        print("Crypto Info: ", crypto_info)
                        print(decrypted_buf)
                        sessionkey = decrypted_buf[entity_server.NONCE_SIZE+crypto_buf_length+crypto_buf:]
                        number_of_sessionkey = entity_server.read_unsigned_int_BE(sessionkey, 4)
                        print("Number of session key: ", number_of_sessionkey)
                        entity_server.parse_sessionkey(sessionkey[4:],session_key)
                        print(session_key)
                        client_sock.close()

                        # first buffer is indicator 1. other buffer is nonce.
                        dec_buf = entity_server.symmetric_decrypt_hmac(session_key, encrypted_buf[:32], encrypted_buf[32:])
                        print(dec_buf)
                        break
                        
                print("Success for receiving the session key.")

            elif recv_data[0] == 32:
                data.outb += "Hello"
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]

host, port = filesystemManager_dir["ip_address"], int(filesystemManager_dir["port_number"])

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    lsock.close()
    sel.close()
    print("Finished")
