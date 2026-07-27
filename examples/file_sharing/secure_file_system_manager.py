import argparse
import os
import sqlite3
import threading
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7

from iotauth import IoTAuthContext, SecureServer

KEY_LEN = 32
PBKDF2_ITER = 1000000
IV_SIZE = 16
SESSION_KEY_ID_SIZE = 8
database_name = "file_system.db"

DATA_UPLOAD_REQ = 0
DATA_DOWNLOAD_REQ = 1
DOWNLOAD_RESP = 2

def get_key(password_str: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive(password_str.encode("utf-8"))

def decrypt_with_password(filename: str, password: str) -> bytes:
    with open(filename, "rb") as f:
        file_data = f.read()
    if len(file_data) < 32:
        raise ValueError("Invalid encrypted file format.")
    salt = file_data[:16]
    iv = file_data[16:32]
    ciphertext = file_data[32:]
    
    key = get_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    try:
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    except Exception:
        print("Invalid password or corrupted file.")
        return None
        
    with open(filename, "wb") as f:
        f.write(decrypted_data)
    print("File decrypted successfully.")
    return decrypted_data

def create_encrypt_database(filename: str, password: str, file_metadata_table: dict, record_history_table: dict):
    con = sqlite3.connect(filename)
    cur = con.cursor()
    cur.execute("CREATE TABLE file_metadata(name, file_keyid, hash_value)")
    
    file_metadata_list = []
    for i, name in enumerate(file_metadata_table["name"]):
        key_id_bytes = file_metadata_table["file_keyid"][i]
        key_id_int = int.from_bytes(key_id_bytes, byteorder='big')
        file_metadata_list.append((name, key_id_int, file_metadata_table["hash_value"][i]))
        
    cur.executemany("INSERT INTO file_metadata VALUES(?, ?, ?)", file_metadata_list)
    
    cur.execute("CREATE TABLE record_metadata(name, file_keyid, hash_value)")
    record_metadata_list = []
    for i, name in enumerate(record_history_table["name"]):
        key_id_bytes = record_history_table["file_keyid"][i]
        key_id_int = int.from_bytes(key_id_bytes, byteorder='big')
        record_metadata_list.append((name, key_id_int, record_history_table["hash_value"][i]))
        
    cur.executemany("INSERT INTO record_metadata VALUES(?, ?, ?)", record_metadata_list)
    con.commit()
    con.close()
    
    salt = os.urandom(16)
    key = get_key(password, salt)
    iv = os.urandom(16)
    
    with open(filename, "rb") as f:
        plaintext = f.read()
        
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(filename, "wb") as f:
        f.write(salt + iv + ciphertext)
    print(f"Encrypted database saved: {filename}")

def database_to_dict(data: tuple, db_dict: dict) -> dict:
    key_id_int = int(data[1])
    key_id_bytes = key_id_int.to_bytes(SESSION_KEY_ID_SIZE, byteorder='big')
    db_dict["name"].append(data[0])
    db_dict["file_keyid"].append(key_id_bytes)
    db_dict["hash_value"].append(data[2])
    return db_dict

def check_database(password: str, file_name: str, file_metadata_table: dict, record_history_table: dict):
    if os.path.isfile(file_name):
        print("Database already exists.")
        number = password if password else input("Press the password for the database: ")
        decrypted_data = decrypt_with_password(file_name, number)
        if decrypted_data is None:
            print("decryption was not applied!!")
            os.remove(file_name)
            return file_metadata_table, record_history_table, number
        
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
        if password:
            number = password
            print("New database generated using password.")
        else:
            number = input("Generate the password for the database: ")
        return file_metadata_table, record_history_table, number

def save_info_for_file(recv_data: bytes, file_metadata_table: dict):
    name_size = recv_data[1]
    name = recv_data[2 : 2 + name_size].decode("utf-8").strip("\x00")
    file_metadata_table["name"].append(name)
    keyid_size = recv_data[2 + name_size]
    file_keyid = recv_data[3 + name_size : 3 + name_size + keyid_size]
    file_metadata_table["file_keyid"].append(file_keyid)
    hash_value_size = recv_data[3 + name_size + keyid_size]
    hash_value = recv_data[
        4 + name_size + keyid_size : 4 + name_size + keyid_size + hash_value_size
    ].decode("utf-8")
    file_metadata_table["hash_value"].append(hash_value)

def download_num_check(name: str, download_list: list) -> int:
    num = 0
    if len(download_list) == 0:
        return num
    for i in download_list:
        if i == name:
            num += 1
    return num

def concat_data(
    recv_data: bytes, file_metadata_table: dict, record_history_table: dict, download_list: list
) -> bytearray:
    name_size = recv_data[1]
    name = recv_data[2 : 2 + name_size].decode("utf-8").strip("\x00")
    file_index = download_num_check(name, download_list)
    res_keyid = file_metadata_table["file_keyid"][file_index]
    res_hashvalue = file_metadata_table["hash_value"][file_index]
    command = "ipfs cat $1 > "
    command = command.replace("$1", res_hashvalue)
    
    message = bytearray(3 + len(res_keyid) + len(command))
    message[0] = DOWNLOAD_RESP
    message[1] = len(res_keyid)
    message[2 : 2 + len(res_keyid)] = res_keyid
    message[2 + len(res_keyid)] = len(command)
    message[3 + len(res_keyid) : 3 + len(res_keyid) + len(command)] = bytes.fromhex(
        str(command).encode("utf-8").hex()
    )
    
    record_history_table["name"].append(name)
    record_history_table["hash_value"].append(res_hashvalue)
    record_history_table["file_keyid"].append(res_keyid)
    
    download_list.append(name)
    return message


# Global state (thread-safe for simple operations in this demo, but locks could be added)
file_metadata_table = {"name":[] , "file_keyid" : [], "hash_value" : []}
record_history_table = {"name":[] , "file_keyid" : [], "hash_value" : []}
download_list = []
db_lock = threading.Lock()

def client_handler(channel):
    try:
        while True:
            recv_data = channel.recv()
            if not recv_data:
                break
                
            print("Received secure message!!")
            msg_type = recv_data[0]
            
            with db_lock:
                if msg_type == DATA_UPLOAD_REQ:
                    save_info_for_file(recv_data, file_metadata_table)
                    print(file_metadata_table)
                elif msg_type == DATA_DOWNLOAD_REQ:
                    response = concat_data(recv_data, file_metadata_table, record_history_table, download_list)
                    channel.send(bytes(response))
    except Exception as e:
        print(f"Connection closed or error: {e}")
    finally:
        channel.close()

def main():
    parser = argparse.ArgumentParser(description="Process config and optional password.")
    parser.add_argument("config", help="Path to config file")
    parser.add_argument("-p", "--password", help="Password for authentication (optional)")
    args = parser.parse_args()

    global file_metadata_table, record_history_table
    file_metadata_table, record_history_table, password = check_database(
        args.password, database_name, file_metadata_table, record_history_table
    )

    ctx = IoTAuthContext.from_config(args.config, validate_paths=False)
    
    with SecureServer(ctx) as server:
        server.listen()
        print(f"Listening for connections on {ctx.config.targets[0].host}:{ctx.config.targets[0].port}...")
        try:
            while True:
                channel = server.serve_once()
                t = threading.Thread(target=client_handler, args=(channel,))
                t.daemon = True
                t.start()
        except KeyboardInterrupt:
            print("Caught keyboard interrupt, exiting")
        finally:
            create_encrypt_database(database_name, password, file_metadata_table, record_history_table)
            print("Finished")

if __name__ == "__main__":
    main()
