import sys
import socket
import selectors
import types
import subprocess
import time
from datetime import datetime
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad

BYTES_NUM = 1024
RSA_KEY_SIZE = 256
SESSION_KEY_ID_SIZE = 8
NONCE_SIZE = 8
ABS_VALIDITY_SIZE = 6
REL_VALIDITY_SIZE = 6
IV_SIZE = 16
AUTH_ID = 4
KEY_NUM_BUF = 4
AUTH_HELLO = 0
SESSION_KEY_REQ_IN_PUB_ENC = 20
SESSION_KEY_RESP_WITH_DIST_KEY = 21
SKEY_HANDSHAKE_1 = 30
def load_config(path: str, filesystem_manager_dir: dict) -> None:
    """Loads configuration data from a file into a provided dictionary.

    Args:
        path (str): The path to the configuration file.
        filesystem_manager_dir (dict): A dictionary where the configuration data will be stored.

    Raises:
        FileNotFoundError: If the file at the given path does not exist.
        IOError: If the file is not readable.
    """
    f = open(path, 'r')
    while True:
        line = f.readline()
        if not line: break
        index = line.split("=")[0]
        content = line.split("=")[1].strip("\n")
        if index == "name":
            filesystem_manager_dir["name"] = content
        elif index == "purpose":
            filesystem_manager_dir["purpose"] = content
        elif index == "number_key":
            filesystem_manager_dir["number_key"] = content
        elif index == "auth_pubkey_path":
            filesystem_manager_dir["auth_pubkey_path"] = content
        elif index == "privkey_path":
            filesystem_manager_dir["privkey_path"] = content
        elif index == "auth_ip_address":
            filesystem_manager_dir["auth_ip_address"] = content
        elif index == "auth_port_number":
            filesystem_manager_dir["auth_port_number"] = content
        elif index == "port_number":
            filesystem_manager_dir["port_number"] = content
        elif index == "ip_address":
            filesystem_manager_dir["ip_address"] = content
        elif index == "network_protocol":
            filesystem_manager_dir["network_protocol"] = content
        else:
            break
    f.close()

def write_in_n_bytes(num_key: int, key_size: int) -> bytearray:
    """Writes an integer into a byte array of specified size.

    Args:
        num_key (int): The integer to convert.
        key_size (int): The size of the resulting byte array.

    Returns:
        bytearray: A byte array representing the integer.
    """
    buffer = bytearray(4)
    for i in range(key_size):
        buffer[i] = num_key >> 8*(key_size-i-1)
    return buffer

def num_to_var_length_int(num: int) -> bytearray:
    """Converts an integer to a variable length byte array.

    Args:
        num (int): The integer to convert.

    Returns:
        bytearray: A variable length byte array representing the integer.
    """
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

def var_length_int_to_num(buffer: bytearray) -> tuple:
    """Converts a variable length byte array back to an integer.

    Args:
        buffer (bytearray): The byte array to convert.

    Returns:
        tuple: A tuple containing the converted integer and the number of bytes read.
    """
    number = 0
    buffer_num = 0
    for i in range(len(buffer)):
        number |= (buffer[i] & 127) << 7*i
        if (buffer[i] & 128) == 0:
            buffer_num = i + 1
            break
    return number, buffer_num

def read_unsigned_int_BE(buffer: bytearray, size: int) -> int:
    """Reads an unsigned integer in big-endian format from the given buffer.

    Args:
        buffer (bytearray): The buffer from which to read.

    Returns:
        int: The read unsigned integer.
    """
    num = 0
    for i in range(size):
       num |= buffer[i] << 8 *(size-1-i)
    return num

def parse_sessionkey(buffer: bytearray, session_key: dict) -> None:
    """Parses session key information from a byte array and stores it in a dictionary.

    Args:
        buffer (bytearray): The buffer containing the session key information.
        session_key (dict): A dictionary to store the parsed session key information.
    """
    index = 0
    session_key["sessionkey_id"] = buffer[:SESSION_KEY_ID_SIZE] 
    index += SESSION_KEY_ID_SIZE
    session_key["abs_validity"] = buffer[index:index+ABS_VALIDITY_SIZE]
    index += ABS_VALIDITY_SIZE
    session_key["rel_validity"] = buffer[index:index+REL_VALIDITY_SIZE]
    index += REL_VALIDITY_SIZE
    cipher_key_size = buffer[index]
    index += 1
    session_key["cipher_key"] = buffer[index:index+cipher_key_size]
    index += cipher_key_size
    mac_key_size = buffer[index]
    index += 1
    session_key["mac_key"] = buffer[index:index+mac_key_size]

def symmetric_encrypt_hmac(key_dir: dict, buffer: bytes) -> tuple:
    """Encrypts data using AES-CBC and appends an HMAC-SHA256 tag.

    Args:
        key_dir (dict): A dictionary containing encryption keys.
        buffer (bytes): The data to be encrypted.

    Returns:
        tuple: A tuple of (encrypted data, HMAC tag).
    """
    padder = pad.PKCS7(128).padder()
    pad_data = padder.update(buffer)
    pad_data += padder.finalize()
    iv = secrets.token_bytes(IV_SIZE)
    cipher = Cipher(algorithms.AES128(key_dir["cipher_key"]),modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_buf = encryptor.update(pad_data) + encryptor.finalize()
    enc_total_buf = bytearray(len(iv) + len(encrypted_buf))
    enc_total_buf[:IV_SIZE] = iv
    enc_total_buf[IV_SIZE:] = encrypted_buf
    h = hmac.HMAC(key_dir["mac_key"], hashes.SHA256(), backend=default_backend())
    h.update(bytes(enc_total_buf))
    hmac_tag = h.finalize()
    return enc_total_buf, hmac_tag

def symmetric_decrypt_hmac(key_dir: dict, enc_buf: bytes, hmac_buf: bytes) -> bytes:
    """Decrypts AES-CBC encrypted data and verifies HMAC-SHA256 tag.

    Args:
        key_dir (dict): A dictionary containing decryption keys.
        enc_buf (bytes): The encrypted data.
        hmac_buf (bytes): The HMAC tag for verification.

    Returns:
        bytes: The decrypted data.

    Raises:
        ValueError: If the HMAC verification fails.
    """
    h = hmac.HMAC(key_dir["mac_key"], hashes.SHA256(), backend=default_backend())
    h.update(bytes(enc_buf))
    hmac_tag = h.finalize()
    if hmac_tag != hmac_buf:
        print("Failed for verifying the data")
        exit()
    else:
        print("Success for verifying the data")
    iv = enc_buf[:IV_SIZE]
    cipher = Cipher(algorithms.AES128(key_dir["cipher_key"]),modes.CBC(bytes(iv)))
    decryptor = cipher.decryptor()
    padded_buf = decryptor.update(bytes(enc_buf[IV_SIZE:])) + decryptor.finalize()
    unpadder = pad.PKCS7(128).unpadder()
    decrypted_buf = unpadder.update(padded_buf) + unpadder.finalize()
    return decrypted_buf

def load_pubkey(key_dir: str) -> rsa.RSAPublicKey:
    """Loads an RSA public key from a file.

    Args:
        key_dir (str): The path to the public key file.

    Returns:
        rsa.RSAPublicKey: The loaded RSA public key.
    """
    with open(key_dir, 'rb') as pem_inn:
        public_key = (x509.load_pem_x509_certificate(pem_inn.read(), default_backend)).public_key()
    return public_key

def load_privkey(key_dir: str) -> rsa.RSAPrivateKey:
    """Loads an RSA private key from a file.

    Args:
        key_dir (str): The path to the private key file.

    Returns:
        rsa.RSAPrivateKey: The loaded RSA private key.
    """
    with open(key_dir, 'rb') as pem_in:
        private_key= serialization.load_pem_private_key(pem_in.read(), None)
    return private_key

def asymmetric_encrypt(message: bytes, pubkey: rsa.RSAPublicKey) -> bytes:
    """Encrypts a message using an RSA public key.

    Args:
        message (bytes): The message to be encrypted.
        pubkey (rsa.RSAPublicKey): The RSA public key for encryption.

    Returns:
        bytes: The encrypted message.
    """
    ciphertext = pubkey.encrypt(bytes(message),padding.PKCS1v15())
    return ciphertext

def asymmetric_decrypt(message: bytes, privkey: rsa.RSAPrivateKey) -> bytes:
    """Decrypts a message using an RSA private key.

    Args:
        message (bytes): The encrypted message.
        privkey (rsa.RSAPrivateKey): The RSA private key for decryption.

    Returns:
        bytes: The decrypted message.
    """
    plaintext = privkey.decrypt(message, padding.PKCS1v15())
    return plaintext

def sha256_sign(message: bytes, privkey: rsa.RSAPrivateKey) -> bytes:
    """Signs a message using SHA256 and an RSA private key.

    Args:
        message (bytes): The message to be signed.
        privkey (rsa.RSAPrivateKey): The RSA private key for signing.

    Returns:
        bytes: The digital signature.
    """
    signature = privkey.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return signature

def sha256_verify(sign: bytes, data: bytes, pubkey: rsa.RSAPublicKey) -> None:
    """Verifies an SHA256 signature using an RSA public key.

    Args:
        sign (bytes): The signature to verify.
        data (bytes): The data that was signed.
        pubkey (rsa.RSAPublicKey): The RSA public key for verification.
    """
    pubkey.verify(sign, data, padding.PKCS1v15(), hashes.SHA256())
    print("auth signature verified\n")

def serialize_message_for_auth(filesystem_manager_dir: dict, nonce_auth: bytes, nonce_entity: bytes) -> bytearray:
    """Serializes message for authentication using given directory and nonce.

    Args:
        filesystem_manager_dir (dict): A directory containing filesystem manager data.
        nonce_auth (bytes): Nonce for authentication.

    Returns:
        tuple: A tuple containing the serialized message and nonce entity.
    """
    buffer_key_len = 4
    max_buffer_len = 4
    message_length = NONCE_SIZE * 2 + buffer_key_len+len(filesystem_manager_dir["name"])
        + len(filesystem_manager_dir["purpose"]) + max_buffer_len * 2
    serialize_message = bytearray(message_length)
    index = 0
    serialize_message[index:8] = nonce_entity
    index += NONCE_SIZE
    serialize_message[index:index+NONCE_SIZE] = nonce_auth
    index += NONCE_SIZE
    buffer_key = write_in_n_bytes(int(filesystem_manager_dir["number_key"]), key_size = buffer_key_len)
    serialize_message[index:index+buffer_key_len] = buffer_key
    index += buffer_key_len
    buffer_name_len = num_to_var_length_int(len(filesystem_manager_dir["name"]))
    serialize_message[index:index+len(buffer_name_len)] = buffer_name_len
    index += len(buffer_name_len)
    serialize_message[index:index+len(filesystem_manager_dir["name"])]
        = bytes.fromhex(str(filesystem_manager_dir["name"]).encode('utf-8').hex())
    index += len(filesystem_manager_dir["name"])
    buffer_purpose_len = num_to_var_length_int(len(filesystem_manager_dir["purpose"]))
    serialize_message[index:+len(buffer_purpose_len)] = buffer_purpose_len
    index += len(buffer_purpose_len)
    serialize_message[index:index+len(filesystem_manager_dir["purpose"])] = bytes.fromhex(str(filesystem_manager_dir["purpose"]).encode('utf-8').hex())
    print(serialize_message)
    
    return serialize_message     

def send_sessionkey_request(ciphertext: bytes, signature: bytes) -> bytearray:
    """Prepares a session key request with the given ciphertext and signature.

    Args:
        ciphertext (bytes): The encrypted data.
        signature (bytes): The signature for the data.

    Returns:
        bytearray: A bytearray containing the session key request.
    """
    num_buffer = num_to_var_length_int(len(ciphertext) + len(signature))

    total_buffer = bytearray(len(num_buffer)+1+len(ciphertext) + len(signature))
    index =0
    total_buffer[index] = SESSION_KEY_REQ_IN_PUB_ENC
    index += 1
    total_buffer[index:index+len(num_buffer)] = num_buffer
    index += len(num_buffer)
    total_buffer[index:index+len(ciphertext)] = ciphertext
    index += len(ciphertext)
    total_buffer[index:index+len(signature)] = signature
    
    return total_buffer

def auth_socket_connect(filesystem_manager_dir: dict) -> socket.socket:
    """Establishes a socket connection for authentication.

    Args:
        filesystem_manager_dir (dict): A directory containing connection details.

    Returns:
        socket.socket: The established socket connection.
    """
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Host = filesystem_manager_dir["auth_ip_address"]
    Port = int(filesystem_manager_dir["auth_port_number"])
    client_sock.connect((Host, Port))
    return client_sock

def parse_sessionkey_id(recv: bytearray, filesystem_manager_dir: dict) -> bytes:
    """Parses session key ID from received data and updates filesystem manager directory.

    Args:
        recv (bytearray): The received data containing the session key ID.
        filesystem_manager_dir (dict): A directory where the session key ID will be updated.

    Returns:
        bytes: The remainder of the received data after extracting the session key ID.
    """
    key_id = recv[:SESSION_KEY_ID_SIZE]
    key_id_int = 0
    for i in range(SESSION_KEY_ID_SIZE):
        key_id_int += (int(key_id[i]) << 8*(7-i))
    filesystem_manager_dir["purpose"] = filesystem_manager_dir["purpose"].replace("00000000", str(key_id_int))
    print(filesystem_manager_dir["purpose"])
    encrypted_buf = recv[SESSION_KEY_ID_SIZE:]
    return encrypted_buf

def parse_distributionkey(buffer: bytearray, pubkey: rsa.RSAPublicKey, privkey: rsa.RSAPrivateKey, distribution_key: dict) -> None:
    """Parses distribution key from the buffer using public and private keys.

    Args:
        buffer (bytearray): The buffer containing the distribution key data.
        pubkey (rsa.RSAPublicKey): The RSA public key for verification.
        privkey (rsa.RSAPrivateKey): The RSA private key for decryption.
        distribution_key (dict): A dictionary to store the parsed distribution key data.
    """
    sign_data = buffer[:RSA_KEY_SIZE]
    sign_sign = buffer[RSA_KEY_SIZE:RSA_KEY_SIZE*2]
    sha256_verify(sign_sign, sign_data, pubkey)
    plaintext = asymmetric_decrypt(sign_data, privkey)
    distribution_key["abs_validity"] = plaintext[:ABS_VALIDITY_SIZE]
    distribution_key["cipher_key"] = plaintext[ABS_VALIDITY_SIZE+1:ABS_VALIDITY_SIZE+1+plaintext[6]]
    distribution_key["mac_key"] = plaintext[ABS_VALIDITY_SIZE+1+1+plaintext[6]:]

def get_session_key(buffer: bytearray, filesystem_manager_dir: dict, sock: socket.socket, distribution_key: dict, session_key: dict, nonce_entity: bytes):
    """Handles the process of receiving and processing a session key.

    Args:
        buffer (bytearray): The input buffer containing the session key information.
        filesystem_manager_dir (dict): The directory information for the filesystem manager.
        sock (socket.socket): The socket for communication.
        distribution_key (dict): The dictionary to store distribution key information.
        session_key (dict): The dictionary to store session key information.
        nonce_entity (bytes): Nonce information.

    Returns:
        None
    """
    # Extract message type and length
    msg_type = buffer[0]
    length, length_buf = var_length_int_to_num(buffer[1:])

    if msg_type == AUTH_HELLO:
        # Handle AUTH_HELLO message
        nonce_auth = buffer[AUTH_ID+1+length_buf:]
        serialize_message = serialize_message_for_auth(filesystem_manager_dir, nonce_auth, nonce_entity)
        ciphertext = asymmetric_encrypt(serialize_message, filesystem_manager_dir['pubkey'])
        signature = sha256_sign(ciphertext, filesystem_manager_dir['privkey'])

        # Send session key request
        total_buffer = send_sessionkey_request(ciphertext, signature)
        sock.send(bytes(total_buffer))
    elif msg_type == SESSION_KEY_RESP_WITH_DIST_KEY:
        # Handle SESSION_KEY_RESP_WITH_DIST_KEY message
        recv_data = buffer[1+length_buf:]
        parse_distributionkey(recv_data, filesystem_manager_dir['pubkey'], filesystem_manager_dir['privkey'], distribution_key)
        
        encrypted_sessionkey = recv_data[RSA_KEY_SIZE*2:]
        
        # Separate encrypted session key and MAC key
        encrypted_buffer = encrypted_sessionkey[:len(encrypted_sessionkey)-len(distribution_key["mac_key"])]
        received_tag = encrypted_sessionkey[len(encrypted_sessionkey)-len(distribution_key["mac_key"]):]

        # Decrypt symmetrically and verify MAC
        decrypted_buf = symmetric_decrypt_hmac(distribution_key, encrypted_buffer, received_tag)
        
        recv_nonce_entity = decrypted_buf[:NONCE_SIZE]
        if nonce_entity != recv_nonce_entity:
            print("Failed for communication with Auth")
            exit()
        else:    
            print("Success for communication with Auth")

        # Interpret encrypted data
        crypto_buf, crypto_buf_length = var_length_int_to_num(decrypted_buf[NONCE_SIZE:])
        crypto_info = decrypted_buf[NONCE_SIZE+crypto_buf_length:NONCE_SIZE+crypto_buf_length+crypto_buf]
        print("Crypto Info: ", crypto_info)
        sessionkey = decrypted_buf[NONCE_SIZE+crypto_buf_length+crypto_buf:]
        number_of_sessionkey = read_unsigned_int_BE(sessionkey, 4)
        print("Number of session key: ", number_of_sessionkey)
        parse_sessionkey(sessionkey[4:], session_key)
        print(session_key)
        print("Success for receiving the session key.")
