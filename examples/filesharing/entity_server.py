import sys
import socket
import selectors
import types
import subprocess
import time
from datetime import datetime
import secrets
bytes_num = 1024
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad

filesystemManager_dir = {"name" : "", "purpose" : '', "number_key":"", "auth_pubkey_path":"", "privkey_path":"", "auth_ip_address":"", "auth_port_number":"", "port_number":"", "ip_address":"", "network_protocol":""}

distribution_key = {"abs_validity" : "", "cipher_key" : "", "mac_key" : ""}
session_key = {"sessionkey_id" : "", "abs_validity" : "", "rel_validity" : "", "cipher_key" : "", "mac_key" : ""}
def load_config(path):
    f = open(path, 'r')
    while True:
        line = f.readline()
        if not line: break
        if line.split("=")[0] == "name":
            filesystemManager_dir["name"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "purpose":
            filesystemManager_dir["purpose"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "number_key":
            filesystemManager_dir["number_key"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "auth_pubkey_path":
            filesystemManager_dir["auth_pubkey_path"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "privkey_path":
            filesystemManager_dir["privkey_path"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "auth_ip_address":
            filesystemManager_dir["auth_ip_address"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "auth_port_number":
            filesystemManager_dir["auth_port_number"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "port_number":
            filesystemManager_dir["port_number"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "ip_address":
            filesystemManager_dir["ip_address"] = line.split("=")[1].strip("\n")
        elif line.split("=")[0] == "network_protocol":
            filesystemManager_dir["network_protocol"] = line.split("=")[1].strip("\n")
        else:
            break
    f.close()
load_config(sys.argv[1])
print(filesystemManager_dir)

sel = selectors.DefaultSelector()

def write_in_n_bytes(num_key, key_size):
    buffer = bytearray(4)
    for i in range(key_size):
        buffer[i] = num_key >> 8*(key_size -1 -i)
    return buffer

def num_to_var_length_int(num):
    var_buf_size = 1
    buffer = bytearray(4)
    while (num > 127):
        buffer[var_buf_size-1] = 128 | num & 127
        var_buf_size += 1
        num >>=7
    buffer[var_buf_size - 1] = num
    buf = bytearray(var_buf_size)
    for i in range(var_buf_size):
        buf[i] = buffer[i]
    return buf

def var_length_int_to_num(buffer):
    number = 0
    buffer_num = 0
    for i in range(len(buffer)):
        number |= (buffer[i] & 127) << 7*i
        if (buffer[i] & 128) == 0:
            buffer_num = i + 1
            break
    return number, buffer_num

def read_unsigned_int_BE(buffer):
    num = 0
    for i in range(4):
       num |= buffer[i] << 8 *(3-i)
    return num

def parse_sessionkey(buffer):
    session_key["sessionkey_id"] = buffer[:8] 
    session_key["abs_validity"] = buffer[8:8+6]
    session_key["rel_validity"] = buffer[8+6:8+6+6]
    cipher_key_size = buffer[8+6+6]
    session_key["cipher_key"] = buffer[8+6+6+1:8+6+6+1+cipher_key_size]
    mac_key_size = buffer[8+6+6+1+cipher_key_size]
    session_key["mac_key"] = buffer[8+6+6+1+cipher_key_size+1:8+6+6+1+cipher_key_size+1+mac_key_size]

def symmetric_encrypt_hmac(key_dir, buffer):
    padder = pad.PKCS7(128).padder()
    pad_data = padder.update(buffer)
    pad_data += padder.finalize()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES128(key_dir["cipher_key"]),modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_buf = encryptor.update(pad_data) + encryptor.finalize()
    enc_total_buf = bytearray(len(iv) + len(encrypted_buf))
    enc_total_buf[:16] = iv
    enc_total_buf[16:] = encrypted_buf
    h = hmac.HMAC(key_dir["mac_key"], hashes.SHA256(), backend=default_backend())
    h.update(bytes(enc_total_buf))
    hmac_tag = h.finalize()
    return enc_total_buf, hmac_tag

def symmetric_decrypt_hmac(key_dir, enc_buf, hmac_buf):
    h = hmac.HMAC(key_dir["mac_key"], hashes.SHA256(), backend=default_backend())
    h.update(bytes(enc_buf))
    hmac_tag = h.finalize()
    if hmac_tag != hmac_buf:
        print("Failed for verifying the data")
        exit()
    else:
        print("Success for verifying the data")
    iv = enc_buf[:16]
    cipher = Cipher(algorithms.AES128(key_dir["cipher_key"]),modes.CBC(bytes(iv)))
    decryptor = cipher.decryptor()
    padded_buf = decryptor.update(bytes(enc_buf[16:])) + decryptor.finalize()
    unpadder = pad.PKCS7(128).unpadder()
    decrypted_buf = unpadder.update(padded_buf) + unpadder.finalize()
    return decrypted_buf

def load_pubkey(key_dir):
    with open(key_dir, 'rb') as pem_inn:
        public_key = (x509.load_pem_x509_certificate(pem_inn.read(), default_backend)).public_key()
    return public_key

def load_privkey(key_dir):
    with open(key_dir, 'rb') as pem_in:
        private_key= serialization.load_pem_private_key(pem_in.read(), None)
    return private_key

def asymmetric_encrypt(message, pubkey):
    ciphertext = pubkey.encrypt(bytes(message),padding.PKCS1v15())
    return ciphertext

def asymmetric_decrypt(message, privkey):
    plaintext = privkey.decrypt(message, padding.PKCS1v15())
    return plaintext

def sha256_sign(message, privkey):
    signature = privkey.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return signature

def sha256_verify(sign, data, pubkey):
    pubkey.verify(sign, data, padding.PKCS1v15(), hashes.SHA256())
    print("auth signature verified\n")

def serialize_message_for_auth(filesystemManager_dir, nonce_auth):
    nonce_entity = secrets.token_bytes(8)
    serialize_message = bytearray(8+8+4+len(filesystemManager_dir["name"])+len(filesystemManager_dir["purpose"])+ 8)
    index = 0
    serialize_message[index:8] = nonce_entity
    index += 8
    serialize_message[index:index+8] = nonce_auth
    index += 8
    buffer = write_in_n_bytes(int(filesystemManager_dir["number_key"]), key_size = 4)
    serialize_message[index:index+4] = buffer
    index += 4
    buffer_name_len = num_to_var_length_int(len(filesystemManager_dir["name"]))
    serialize_message[index:index+len(buffer_name_len)] = buffer_name_len
    index += len(buffer_name_len)
    serialize_message[index:index+len(filesystemManager_dir["name"])] = bytes.fromhex(str(filesystemManager_dir["name"]).encode('utf-8').hex())
    index += len(filesystemManager_dir["name"])
    buffer_purpose_len = num_to_var_length_int(len(filesystemManager_dir["purpose"]))
    serialize_message[index:+len(buffer_purpose_len)] = buffer_purpose_len
    index += len(buffer_purpose_len)
    serialize_message[index:index+len(filesystemManager_dir["purpose"])] = bytes.fromhex(str(filesystemManager_dir["purpose"]).encode('utf-8').hex())
    print(serialize_message)
    
    return serialize_message, nonce_entity     

def send_sessionkey_request(ciphertext, signature):
    num_buffer = num_to_var_length_int(len(ciphertext) + len(signature))

    total_buffer = bytearray(len(num_buffer)+1+len(ciphertext) + len(signature))
    index =0
    total_buffer[index] = 20
    index += 1
    total_buffer[index:index+len(num_buffer)] = num_buffer
    index += len(num_buffer)
    total_buffer[index:index+len(ciphertext)] = ciphertext
    index += len(ciphertext)
    total_buffer[index:index+len(signature)] = signature
    
    return total_buffer

def auth_socket_connect(filesystemManager_dir):
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Host = filesystemManager_dir["auth_ip_address"]
    Port = int(filesystemManager_dir["auth_port_number"])
    client_sock.connect((Host, Port))
    return client_sock

def parse_sessionkey_id(recv, filesystemManager_dir):
    key_id = recv[2:2+8]
    key_id_int = (int(key_id[5]) << 16) + (int(key_id[6]) << 8) +(int(key_id[7]))
    filesystemManager_dir["purpose"] = filesystemManager_dir["purpose"].replace("00000000", str(key_id_int))
    print(filesystemManager_dir["purpose"])
    encrypted_buf = recv[10:]
    return encrypted_buf
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
        recv_data = sock.recv(bytes_num)  # Should be ready to read
        if recv_data:
            if recv_data[0] == 30:
                encrypted_buf = parse_sessionkey_id(recv_data, filesystemManager_dir)
                client_sock = auth_socket_connect(filesystemManager_dir)
                public_key = load_pubkey(filesystemManager_dir["auth_pubkey_path"])
                private_key = load_privkey(filesystemManager_dir["privkey_path"])
                while(1):
                    recv_data_from_auth = client_sock.recv(1024)
                    if len(recv_data_from_auth) == 0:
                        continue
                    msg_type = recv_data_from_auth[0]
                    length, length_buf = var_length_int_to_num(recv_data_from_auth[1:])
                    if msg_type == 0:
                        nonce_auth = recv_data_from_auth[4+1+length_buf:]
                        serialize_message, nonce_entity = serialize_message_for_auth(filesystemManager_dir, nonce_auth)
                        
                        ciphertext = asymmetric_encrypt(serialize_message, public_key)
                        signature = sha256_sign(ciphertext, private_key)
                        
                        total_buffer = send_sessionkey_request(ciphertext, signature)
                        client_sock.send(bytes(total_buffer))

                    elif msg_type == 21:
                        recv_data = recv_data_from_auth[1+length_buf:]
                        rsa_key_size = 256
                        sign_data = recv_data[:rsa_key_size]
                        sign_sign = recv_data[rsa_key_size:rsa_key_size*2]

                        sha256_verify(sign_sign, sign_data, public_key)
                        plaintext = asymmetric_decrypt(sign_data, private_key)

                        distribution_key["abs_validity"] = plaintext[:6]
                        distribution_key["cipher_key"] = plaintext[7:7+plaintext[6]]
                        distribution_key["mac_key"] = plaintext[8+16:]

                        encrytped_sessionkey = recv_data[rsa_key_size*2:]
                        
                        encrypted_buffer = encrytped_sessionkey[:len(encrytped_sessionkey)-len(distribution_key["mac_key"])]
                        received_tag = encrytped_sessionkey[len(encrytped_sessionkey)-len(distribution_key["mac_key"]):]

                        decrypted_buf = symmetric_decrypt_hmac(distribution_key, encrypted_buffer, received_tag)
                        
                        recv_nonce_entity = decrypted_buf[:8]
                        if nonce_entity != recv_nonce_entity:
                            print("Failed for communication with Auth")
                            exit()
                        else:    
                            print("Success for communication with Auth")

                        crypto_buf, crypto_buf_length = var_length_int_to_num(decrypted_buf[8:])
                        crypto_info = decrypted_buf[8+crypto_buf_length:8+crypto_buf_length+crypto_buf]
                        print("Crypto Info: ", crypto_info)
                        sessionkey = decrypted_buf[8+crypto_buf_length+crypto_buf:]
                        number_of_sessionkey = read_unsigned_int_BE(sessionkey)
                        print("Number of session key: ", number_of_sessionkey)
                        parse_sessionkey(sessionkey[4:])
                        client_sock.close()

                        # first buffer is indicator 1. other buffer is nonce.
                        dec_buf = symmetric_decrypt_hmac(session_key, encrypted_buf[:32], encrypted_buf[32:])
                        break
                        
                print("Success for receiving the session key.")

            elif recv_data[0] == 32:
                data.outb += "Hello"
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)

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


# TODO: Send the message and receive the message -> Success of the secure communication
# TODO: Apply SST to communication between file system manager and entities