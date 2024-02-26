import socket
import selectors
import types
from datetime import datetime


bytes_num = 1024
DATA_UPLOAD_REQ = 0
DATA_DOWNLOAD_REQ = 1
DATA_RESP = 2
sel = selectors.DefaultSelector()

# Save information such as hash value, sessionkey id, and name received from uploader entity.
def save_data(recv_data, file_center):
    name_size = recv_data[1]
    name = recv_data[2:2+name_size].decode('utf-8').strip("\x00")
    file_center["name"].append(name)
    keyid_size = recv_data[2+name_size]
    keyid = recv_data[3+name_size:3+name_size+keyid_size]
    file_center["keyid"].append(keyid)
    hash_value_size = recv_data[3+name_size+keyid_size]
    hash_value = recv_data[4+name_size+keyid_size:4+name_size+keyid_size+hash_value_size].decode('utf-8')
    file_center["hash_value"].append(hash_value)

# Concat data to send the information including hash value, sessionkey id, and name to downloader entity.
def concat_data(recv_data):
    name_size = recv_data[1]
    name = recv_data[2:2+name_size].decode('utf-8').strip("\x00")
    file_index = download_num_check(name)
    res_keyid = file_center["keyid"][file_index]
    res_hashvalue = file_center["hash_value"][file_index]
    command = "ipfs cat $1 > "
    command = command.replace("$1", res_hashvalue)
    message = bytearray(3+len(res_keyid)+len(command))
    message[0] = int(hex(DATA_RESP),16)
    message[1] = int(hex(len(res_keyid)),16)
    message[2:2+len(res_keyid)] = res_keyid
    message[2+len(res_keyid)] = int(hex(len(command)),16)
    message[3+len(res_keyid):3+len(res_keyid)+len(command)] = bytes.fromhex(str(command).encode('utf-8').hex())
    log_center["name"].append(name), log_center["hash_value"].append(res_hashvalue), log_center["keyid"].append(res_keyid)
    download_list.append(name)
    return message

# Check how many times the entity has downloaded the file.
def download_num_check(name):
    num = 0
    if len(download_list) == 0:
        return num
    for i in download_list:
        if i == name:
            num += 1
    return num      

def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

file_center = {"name":[] , "keyid" : [], "hash_value" : []}
log_center = {"name":[] , "keyid" : [], "hash_value" : []}
download_list = []
def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    global payload_max_num
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(bytes_num) # Should be ready to read
        if recv_data:
            print(recv_data)
            if recv_data[0] == DATA_UPLOAD_REQ:
                save_data(recv_data, file_center)
                print(file_center)
            elif recv_data[0] == DATA_DOWNLOAD_REQ:
                message = concat_data(recv_data)
                data.outb += message
                sent = sock.send(data.outb) 
                data.outb = data.outb[sent:]
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)

    
port = 22100
host, port = '127.0.0.1', port

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
    print("-------------LOG result-------------")
    print(log_center)
    
    print("Finished")
