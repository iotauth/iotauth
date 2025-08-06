import socket
import os
import sqlite3
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

KEY_LEN = 32
PBKDF2_ITER = 480_000
READ_BYTES_NUM = 1024
RSA_KEY_SIZE = 256
SESSION_KEY_ID_SIZE = 8
NONCE_SIZE = 8
ABS_VALIDITY_SIZE = 6
REL_VALIDITY_SIZE = 6
IV_SIZE = 16
AUTH_ID_LEN = 4
KEY_NUM_BUF = 4
SEQ_NUM_SIZE = 8
AUTH_HELLO = 0
SESSION_KEY_REQ_IN_PUB_ENC = 20
SESSION_KEY_RESP_WITH_DIST_KEY = 21
SKEY_HANDSHAKE_1 = 30
SKEY_HANDSHAKE_2 = 31
SKEY_HANDSHAKE_3 = 32
SECURE_COMM_MSG = 33
MAC_KEY_SIZE = 32
DATA_UPLOAD_REQ = 0
DATA_DOWNLOAD_REQ = 1
DOWNLOAD_RESP = 2
database_name = "file_system_manager.db"

def load_config(path: str, config_dict: dict) -> None:
    """Loads configuration data from a file into a provided dictionary.

    Args:
        path (str): The path to the configuration file.
        config_dict (dict): A dictionary where the configuration data will be stored.

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
            config_dict["name"] = content
        elif index == "purpose":
            config_dict["purpose"] = content
        elif index == "number_key":
            config_dict["number_key"] = content
        elif index == "authid":
            config_dict["authid"] = content
        elif index == "auth_pubkey_path":
            config_dict["auth_pubkey_path"] = content
        elif index == "privkey_path":
            config_dict["privkey_path"] = content
        elif index == "auth_ip_address":
            config_dict["auth_ip_address"] = content
        elif index == "auth_port_number":
            config_dict["auth_port_number"] = content
        elif index == "port_number":
            config_dict["port_number"] = content
        elif index == "ip_address":
            config_dict["ip_address"] = content
        elif index == "network_protocol":
            config_dict["network_protocol"] = content
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
    buffer = bytearray(key_size)
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
        buffer[var_buf_size - 1] = 128 | num & 127
        var_buf_size += 1
        num >>= 7
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

def symmetric_encrypt_hmac(key_dir: dict, buffer: bytes) -> bytearray:
    """Encrypts data using AES-CBC and appends an HMAC-SHA256 tag.

    Args:
        key_dir (dict): A dictionary containing encryption keys.
        buffer (bytes): The data to be encrypted.

    Returns:
        bytearray: IV + ciphertext + HMAC tag
    """
    # Padding (PKCS#7)
    pad_data = pad(buffer, AES.block_size)

    # Generate IV
    iv = get_random_bytes(IV_SIZE)

    # AES-CBC encryption
    cipher = AES.new(key_dir["cipher_key"], AES.MODE_CBC, iv)
    encrypted_buf = cipher.encrypt(pad_data)

    # Combine IV and ciphertext
    enc_total_buf = iv + encrypted_buf

    # Compute HMAC-SHA256
    h = HMAC.new(key_dir["mac_key"], digestmod=SHA256)
    h.update(enc_total_buf)
    hmac_tag = h.digest()

    # Final output: IV + ciphertext + HMAC
    return bytearray(enc_total_buf + hmac_tag)

def symmetric_decrypt_hmac(key_dir: dict, enc_buf: bytes, hmac_buf: bytes) -> bytes:
    """Decrypts AES-CBC encrypted data and verifies HMAC-SHA256 tag.

    Args:
        key_dir (dict): A dictionary containing decryption keys.
        enc_buf (bytes): The encrypted data.
        hmac_buf (bytes): The HMAC tag for verification.

    Returns:
        bytes: The decrypted data.

    Raises:
        ValueError: If HMAC verification fails.
    """
    # Verify HMAC
    h = HMAC.new(key_dir["mac_key"], digestmod=SHA256)
    h.update(enc_buf)
    try:
        h.verify(hmac_buf)
        print("HMAC verification succeeded.")
    except ValueError:
        print("HMAC verification failed.")
        raise ValueError("Authentication failed: HMAC does not match.")

    # Extract IV and ciphertext
    iv = enc_buf[:IV_SIZE]
    ciphertext = enc_buf[IV_SIZE:]

    # AES-CBC decryption
    cipher = AES.new(key_dir["cipher_key"], AES.MODE_CBC, iv)
    padded_buf = cipher.decrypt(ciphertext)

    # Remove padding (PKCS#7)
    decrypted_buf = unpad(padded_buf, AES.block_size)

    return decrypted_buf

def load_pubkey(key_dir: str) -> RSA.RsaKey:
    """Loads an RSA public key from a file.

    Args:
        key_dir (str): The path to the public key file.

    Returns:
         RSA.RsaKey: The loaded RSA public key.
    """
    try:
        if not os.path.isfile(key_dir):
            raise FileNotFoundError(f"Key file not found: {key_dir}")

        with open(key_dir, "r") as f:
            key_data = f.read()

        public_key = RSA.import_key(key_data)
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}")
    except ValueError as e:
        print(f"[ERROR] Invalid public key format: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error while loading public key: {e}")
    return public_key

def load_privkey(key_dir: str) -> RSA.RsaKey:
    """Loads an RSA private key from a file.

    Args:
        key_dir (str): The path to the private key file.

    Returns:
        RSA.RsaKey: The loaded RSA private key.
    """
    try:
        if not os.path.exists(key_dir):
            raise FileNotFoundError(f"Key file not found: {key_dir}")

        with open(key_dir, "r") as f:
            key_data = f.read()

        private_key = RSA.import_key(key_data)
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}")
    except ValueError as e:
        print(f"[ERROR] Invalid key format or corrupt PEM: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error while loading private key: {e}")
    return private_key

def asymmetric_encrypt(message: bytes, pubkey: RSA.RsaKey) -> bytes:
    """Encrypts a message using an RSA public key.

    Args:
        message (bytes): The message to be encrypted.
        pubkey (RSA.RsaKey): The RSA public key for encryption.

    Returns:
        bytes: The encrypted message.
    """
    # Create a PKCS1_OAEP cipher object with the public key
    cipher = PKCS1_OAEP.new(pubkey)
    # Encrypt the message
    ciphertext = cipher.encrypt(bytes(message))
    return ciphertext

def asymmetric_decrypt(message: bytes, privkey: RSA.RsaKey) -> bytes:
    """Decrypts a message using an RSA private key.

    Args:
        message (bytes): The encrypted message.
        privkey (RSA.RsaKey): The RSA private key for decryption.

    Returns:
        bytes: The decrypted message.
    """
    # Create cipher object with the private key
    cipher = PKCS1_OAEP.new(privkey)

    # Decrypt the ciphertext
    plaintext = cipher.decrypt(message)
    return plaintext


def sha256_sign(message: bytes, privkey: RSA.RsaKey) -> bytes:
    """Signs a message using SHA256 and an RSA private key.

    Args:
        message (bytes): The message to be signed.
        privkey (RSA.RsaKey): The RSA private key.

    Returns:
        bytes: The digital signature.
    """
    h = SHA256.new(message)
    signature = pkcs1_15.new(privkey).sign(h)
    return signature

def sha256_verify(sign: bytes, data: bytes, pubkey: RSA.RsaKey) -> None:
    """Verifies an SHA256 signature using an RSA public key.

    Args:
        sign (bytes): The signature to verify.
        data (bytes): The data that was signed.
        pubkey (RSA.RsaKey): The RSA public key for verification.
    """
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, sign)
        print("Signature successfully verified.\n")
    except (ValueError, TypeError):
        print(" verification failed.")
        raise

def serialize_message_for_auth(config_dict: dict, nonce_auth: bytes, nonce_entity: bytes) -> bytearray:
    """Serializes message for authentication using given directory and nonce.

    Args:
        config_dict (dict): A directory containing filesystem manager data.
        nonce_auth (bytes): Nonce for authentication.

    Returns:
        tuple: A tuple containing the serialized message and nonce entity.
    """
    buffer_key_len = 4
    max_buffer_len = 4
    message_length = (NONCE_SIZE * 2 + buffer_key_len+len(config_dict["name"]) 
                                     + len(config_dict["purpose"]) + max_buffer_len * 2)
    serialize_message = bytearray(message_length)
    index = 0
    serialize_message[index:8] = nonce_entity
    index += NONCE_SIZE
    serialize_message[index:index+NONCE_SIZE] = nonce_auth
    index += NONCE_SIZE
    buffer_key = write_in_n_bytes(int(config_dict["number_key"]), key_size = buffer_key_len)
    serialize_message[index:index+buffer_key_len] = buffer_key
    index += buffer_key_len
    buffer_name_len = num_to_var_length_int(len(config_dict["name"]))
    serialize_message[index:index+len(buffer_name_len)] = buffer_name_len
    index += len(buffer_name_len)
    serialize_message[index:index+len(config_dict["name"])] = str(config_dict["name"]).encode('utf-8')
    index += len(config_dict["name"])
    buffer_purpose_len = num_to_var_length_int(len(config_dict["purpose"]))
    serialize_message[index:+len(buffer_purpose_len)] = buffer_purpose_len
    index += len(buffer_purpose_len)
    serialize_message[index:index+len(config_dict["purpose"])] = str(config_dict["purpose"]).encode('utf-8')
    print(serialize_message)
    return serialize_message     

def auth_socket_connect(config_dict: dict) -> socket.socket:
    """Establishes a socket connection for authentication.

    Args:
        config_dict (dict): A directory containing connection details.

    Returns:
        socket.socket: The established socket connection.
    """
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    Host = config_dict["auth_ip_address"]
    Port = config_dict["auth_port_number"]
    client_sock.connect((Host, int(Port)))
    return client_sock

def parse_sessionkey_id(recv: bytearray, config_dict: dict) -> bytes:
    """Parses session key ID from received data and updates filesystem manager directory.

    Args:
        recv (bytearray): The received data containing the session key ID.
        config_dict (dict): A directory where the session key ID will be updated.

    Returns:
        bytes: The remainder of the received data after extracting the session key ID.
    """
    key_id = recv[:SESSION_KEY_ID_SIZE]
    key_id_int = 0
    for i in range(SESSION_KEY_ID_SIZE):
        key_id_int += (int(key_id[i]) << 8*(7-i))
    # Change key id for purpose
    config_dict["purpose"] = f'{{"keyId": {str(key_id_int)}}}'
    print(config_dict["purpose"])
    encrypted_buf = recv[SESSION_KEY_ID_SIZE:]
    return encrypted_buf

def parse_distributionkey(buffer: bytearray, pubkey: RSA.RsaKey, privkey: RSA.RsaKey, distribution_key: dict) -> None:
    """Parses distribution key from the buffer using public and private keys.

    Args:
        buffer (bytearray): The buffer containing the distribution key data.
        pubkey (RSA.RsaKey): The RSA public key for verification.
        privkey (RSA.RsaKey): The RSA private key for decryption.
        distribution_key (dict): A dictionary to store the parsed distribution key data.
    """
    sign_data = buffer[:RSA_KEY_SIZE]
    sign_sign = buffer[RSA_KEY_SIZE:RSA_KEY_SIZE*2]
    sha256_verify(sign_sign, sign_data, pubkey)
    plaintext = asymmetric_decrypt(sign_data, privkey)
    distribution_key["abs_validity"] = plaintext[:ABS_VALIDITY_SIZE]
    distribution_key["cipher_key"] = plaintext[ABS_VALIDITY_SIZE+1:ABS_VALIDITY_SIZE+1+plaintext[6]]
    distribution_key["mac_key"] = plaintext[ABS_VALIDITY_SIZE+1+1+plaintext[6]:]

def get_session_key(buffer: bytearray, config_dict: dict, sock: socket.socket, distribution_key: dict, session_key: dict, nonce_entity: bytes):
    """Handles the process of receiving and processing a session key.

    Args:
        buffer (bytearray): The input buffer containing the session key information.
        config_dict (dict): The directory information for the filesystem manager.
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
        # Extract and validate auth_id (big-endian)
        received_auth_id = read_unsigned_int_BE(buffer[1+length_buf:], AUTH_ID_LEN)
        expected_auth_id = int(config_dict['authid'])
        if received_auth_id != expected_auth_id:
            print("Auth ID NOT matched.")
            return 
        # Handle AUTH_HELLO message
        nonce_auth = buffer[AUTH_ID_LEN+1+length_buf:]
        serialize_message = serialize_message_for_auth(config_dict, nonce_auth, nonce_entity)
        ciphertext = asymmetric_encrypt(serialize_message, config_dict['pubkey'])
        signature = sha256_sign(ciphertext, config_dict['privkey'])
        buffer = bytearray(len(ciphertext)+len(signature))
        buffer[:len(ciphertext)] = ciphertext
        buffer[len(ciphertext):] = signature
        # Send session key request
        total_buffer = make_sender_buffer(buffer, SESSION_KEY_REQ_IN_PUB_ENC)
        sock.send(bytes(total_buffer))
    elif msg_type == SESSION_KEY_RESP_WITH_DIST_KEY:
        # Handle SESSION_KEY_RESP_WITH_DIST_KEY message
        recv_data = buffer[1+length_buf:]
        parse_distributionkey(recv_data, config_dict['pubkey'], config_dict['privkey'], distribution_key)
        
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

def serialize_handshake(nonce: bytearray, reply_nonce: bytearray) -> bytearray:
    """Serializes the handshake data into a bytearray.

    Args:
        nonce (bytearray): The nonce for the handshake.
        reply_nonce (bytearray): The reply nonce for the handshake.

    Returns:
        bytearray: The serialized handshake data.
    """
    if (nonce == None) & (reply_nonce == None):
        print("Error: handshake should include at least one nonce.\n")

    indicator = 0
    buffer = bytearray(NONCE_SIZE * 2 + 1)

    if (nonce != None):
        indicator += 1
        buffer[1:1+NONCE_SIZE] = nonce

    if (reply_nonce != None):
        indicator += 1
        buffer[1+NONCE_SIZE:1+NONCE_SIZE*2] = reply_nonce

    buffer[0] = indicator
    return buffer

def make_sender_buffer(buffer: bytearray, msg_type: int) -> bytearray:
    """Creates a buffer for sending messages.

    Args:
        buffer (bytearray): The message buffer.
        msg_type (int): The message type.

    Returns:
        bytearray: The total buffer for sending.
    """
    num_buffer = num_to_var_length_int(len(buffer))
    total_buffer = bytearray(len(num_buffer) + 1 + len(buffer))
    index = 0
    total_buffer[index] = msg_type
    index += 1
    total_buffer[index:index + len(num_buffer)] = num_buffer
    index += len(num_buffer)
    total_buffer[index:] = buffer    
    return total_buffer

def parse_received_message(buffer: bytearray) -> tuple:
    """Parses a received message buffer.

    Args:
        buffer (bytearray): The buffer containing the received message.

    Returns:
        tuple: A tuple containing the message type and the received message.
    """
    msg_type = buffer[0]
    num, buf_num = var_length_int_to_num(buffer[1:])
    received_message = buffer[1+buf_num:1+buf_num+num]
    return msg_type, received_message


def read_int_from_buf(buffer: bytearray, length: int):
    """Reads an integer value from the buffer.

    Args:
        buffer (bytearray): The buffer containing the integer.
        length (int): The length of the integer in bytes.

    Returns:
        int: The integer value.
    """
    num = 0
    for i in range(length):
        num |= buffer[i] << 8 * (length - 1 - i)
    return num
def concat_data(recv_data: bytearray, file_metadata_table: dict, record_history_table: dict, download_list: list) -> bytearray:
    """Concatenates data for a response message.

    Args:
        recv_data (bytearray): The received data.
        file_metadata_table (dict): Dictionary containing file information.
        record_history_table (dict): Dictionary containing log information.
        download_list (list): List of downloaded files.

    Returns:
        bytearray: The concatenated message.
    """
    name_size = recv_data[1]
    name = recv_data[2:2+name_size].decode('utf-8').strip("\x00")
    file_index = download_num_check(name, download_list)
    res_keyid = file_metadata_table["file_keyid"][file_index]
    res_hashvalue = file_metadata_table["hash_value"][file_index]
    command = "ipfs cat $1 > "
    command = command.replace("$1", res_hashvalue)
    message = bytearray(3+len(res_keyid)+len(command))
    message[0] = int(hex(DOWNLOAD_RESP),16)
    print(message[0])
    message[1] = int(hex(len(res_keyid)),16)
    message[2:2+len(res_keyid)] = res_keyid
    message[2+len(res_keyid)] = int(hex(len(command)),16)
    message[3+len(res_keyid):3+len(res_keyid)+len(command)] = bytes.fromhex(str(command).encode('utf-8').hex())
    record_history_table["name"].append(name), record_history_table["hash_value"].append(res_hashvalue), record_history_table["file_keyid"].append(res_keyid)
    download_list.append(name)
    return message

def download_num_check(name: str, download_list: dict) -> int:
    """Checks the number of times a file has been downloaded.

    Args:
        name (str): The name of the file.
        download_list (list): List of downloaded files.

    Returns:
        int: The number of times the file has been downloaded.
    """
    num = 0
    if len(download_list) == 0:
        return num
    for i in download_list:
        if i == name:
            num += 1
    return num  

def save_info_for_file(recv_data: bytearray, file_metadata_table: dict):
    """Saves file information.

    Args:
        recv_data (bytearray): The received data.
        file_metadata_table (dict): Dictionary containing file information.

    Returns:
        None
    """
    name_size = recv_data[1]
    name = recv_data[2:2+name_size].decode('utf-8').strip("\x00")
    file_metadata_table["name"].append(name)
    keyid_size = recv_data[2+name_size]
    file_keyid = recv_data[3+name_size:3+name_size+keyid_size]
    file_metadata_table["file_keyid"].append(file_keyid)
    hash_value_size = recv_data[3+name_size+keyid_size]
    hash_value = recv_data[4+name_size+keyid_size:4+name_size+keyid_size+hash_value_size].decode('utf-8')
    file_metadata_table["hash_value"].append(hash_value)

def metadata_response(dec_buf: bytearray, file_metadata_table: dict, record_history_table: dict, download_list: list, session_key: dict, sequential_num: int) -> bytearray:
    """Generates a response message for data.

    Args:
        dec_buf (bytearray): The decrypted buffer.
        file_metadata_table (dict): Dictionary containing file information.
        record_history_table (dict): Dictionary containing log information.
        download_list (list): List of downloaded files.
        session_key (dict): Dictionary containing session key information.
        sequential_num (int): Sequential number.

    Returns:
        bytearray: The response message.
    """
    seq_buffer = write_in_n_bytes(sequential_num, SEQ_NUM_SIZE)
    message = concat_data(dec_buf[SEQ_NUM_SIZE:], file_metadata_table, record_history_table, download_list)
    total_message = bytearray(SEQ_NUM_SIZE + len(message))
    total_message[:SEQ_NUM_SIZE - 1] = seq_buffer
    total_message[SEQ_NUM_SIZE:] = message
    enc_buffer = symmetric_encrypt_hmac(session_key, total_message)
    return make_sender_buffer(enc_buffer, SECURE_COMM_MSG)

def dict_to_tuple(metadata_dict: dict) -> list:
    """
    Converts a dictionary to a list of tuples.

    Args:
        metadata_dict (dict): The dictionary to be converted.

    Returns:
        list: A list of tuples containing the dictionary data.
    """
    tuple_list = []
    for i, name in enumerate(metadata_dict['name']):
        key_id_int = sum(int(byte) << (8 * (7-j)) for j, byte in enumerate(metadata_dict['file_keyid'][i]))
        tuple_list.append((name, key_id_int, metadata_dict['hash_value'][i]))
    return tuple_list

def create_encrypt_database(filename: str, number: str, file_metadata_table: dict, record_history_table: dict) -> None:
    """
    Encrypts a file using a password and writes it.

    Args:
        filename (str): The name of the file to be encrypted.
        number (str): The password used for encryption.
        file_metadata_table (dict): Metadata for file records.
        record_history_table (dict): Metadata for record files.

    Returns:
        None
    """
    con = sqlite3.connect(filename)
    cur = con.cursor()
    cur.execute("CREATE TABLE file_metadata(name, file_keyid, hash value)")
    file_metadata_list = dict_to_tuple(file_metadata_table)
    cur.executemany("INSERT INTO file_metadata VALUES(?, ?, ?)", file_metadata_list)
    cur.execute("CREATE TABLE record_metadata(name, file_keyid, hash value)")
    record_metadata_list = dict_to_tuple(record_history_table)
    cur.executemany("INSERT INTO record_metadata VALUES(?, ?, ?)", record_metadata_list)
    con.commit()
    con.close()

    salt = bytes(16)
    password_bytes = number.encode("utf-8")
    key = PBKDF2(password_bytes, salt, dkLen=KEY_LEN, count=PBKDF2_ITER)
    with open(filename, "rb") as f:
        plaintext = f.read()

    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    with open(filename, "wb") as f:
        f.write(salt + iv + ciphertext)

    print(f"Encrypted database saved: {filename}")

def decrypt_with_password(filename: str, number: str) -> bytes:
    """
    Decrypts a file using AES-CBC and a password-derived key.

    Args:
        filename (str): The encrypted file path.
        number (str): The password used to derive the decryption key.

    Returns:
        bytes: The decrypted file data.

    Raises:
        ValueError: If decryption or unpadding fails (e.g., wrong password).
    """
    with open(filename, "rb") as file:
        file_data = file.read()

    if len(file_data) < 32:
        raise ValueError("Invalid encrypted file format.")

    # Extract salt, IV, and ciphertext
    salt = file_data[:16]
    iv = file_data[16:32]
    ciphertext = file_data[32:]

    # Derive key from password
    password_bytes = number.encode("utf-8")
    key = PBKDF2(password_bytes, salt, dkLen=KEY_LEN, count=PBKDF2_ITER)

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        decrypted_data = unpad(padded_data, AES.block_size)
    except (ValueError, KeyError):
        print("Invalid password or corrupted file.")
        return None

    with open(filename, "wb") as file:
        file.write(decrypted_data)

    print("File decrypted successfully.")
    return decrypted_data

def database_to_dict(data: str, dict: dict) -> dict:
    """
    Converts database data into a dictionary.

    Args:
        data (str): Data retrieved from the database.
        dict (dict): The dictionary to store the data.

    Returns:
        dict: The updated dictionary with database data.
    """
    key_id_int = int(data[1])
    key_id_bytes = bytearray(SESSION_KEY_ID_SIZE)
    for k in range(SESSION_KEY_ID_SIZE):
        key_id_bytes[k] = key_id_int >> 8 * (7-k)
        key_id_int -= key_id_bytes[k] << 8 * (7-k)
    dict['name'].append(data[0])
    dict['file_keyid'].append(key_id_bytes)
    dict['hash_value'].append(data[2])
    return dict

def check_database(password, file_name: str, file_metadata_table: dict, record_history_table: dict) -> tuple:
    """
    Checks the existence of a database and retrieves its content.

    Args:
        file_name (str): The name of the database file.
        file_metadata_table (dict): Metadata for file records.
        record_history_table (dict): Metadata for record files.

    Returns:
        tuple: Metadata tables and the password used for decryption.
    """
    if os.path.isfile(file_name):
        print("Database already exists.")
        if (password):
            number = password
        else :
            number = input("Press the password for the database: ")
        decrypted_data = decrypt_with_password(file_name, number)
        if decrypted_data == None:
            print("decryption was not applied!!")
            os.remove(file_name)
            return file_metadata_table, record_history_table, number
        else:
            con = sqlite3.connect(file_name)
            cur = con.cursor()
            for row in cur.execute("SELECT * FROM file_metadata"):
                file_metadata_table = database_to_dict(row, file_metadata_table)
            for row in cur.execute("SELECT * FROM record_metadata"):
                record_history_table = database_to_dict(row, record_history_table)
            con.close()
            os.remove(file_name)
            print(file_metadata_table, record_history_table)
            return file_metadata_table, record_history_table, number
                
    else:
        print("Database does not exist.")
        if (password):
            number = password
            print("New database generated using password.")
        else :
            number = input("Generate the password for the database: ")
        return file_metadata_table, record_history_table, number