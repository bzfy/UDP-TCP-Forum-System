import socket, sys, threading
import time
from threading import Thread
from queue import Queue
import os
from threading import Lock



# tls_utility
###########################
import hashlib
import random

def generate_rsa_keypair():
    # random prime number
    primes = [53, 59, 61, 67, 71, 73, 79, 83]
    p = random.choice(primes)
    q = random.choice([x for x in primes if x != p])

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17

    while phi % e == 0:
        e += 2

    d = pow(e, -1, phi)
    return (e, n), (d, n)

def hash_data(data: str):
    return int(hashlib.sha256(data.encode()).hexdigest(), 16)

def rsa_sign(message, privkey):
    h = hash_data(message)
    return pow(h % privkey[1], privkey[0], privkey[1])

def rsa_verify(message, signature, pubkey):
    h = hash_data(message) % pubkey[1]             
    check = pow(signature, pubkey[0], pubkey[1])
    return h == check

def generate_certificate_chain():
    root_pub, root_priv = (17, 3233), (2753, 3233)
    inter_pub, inter_priv = generate_rsa_keypair()
    server_pub, server_priv = generate_rsa_keypair()

    root_cert = {
        "name": "RootCA",
        "pubkey": root_pub,
        "signed_by": "self",
        "signature": rsa_sign("RootCA" + str(root_pub), root_priv)
    }

    inter_cert = {
        "name": "IntermediateCA",
        "pubkey": inter_pub,
        "signed_by": "RootCA",
        "signature": rsa_sign("IntermediateCA" + str(inter_pub), root_priv)
    }

    server_cert = {
        "name": "MyServer",
        "pubkey": server_pub,
        "signed_by": "IntermediateCA",
        "signature": rsa_sign("MyServer" + str(server_pub), inter_priv)
    }

    chain = [server_cert, inter_cert, root_cert]
    return chain, server_priv, root_pub

def serialize_cert(cert):
    name = cert["name"]
    pubkey = f"{cert['pubkey'][0]},{cert['pubkey'][1]}"
    signed_by = cert["signed_by"]
    signature = str(cert["signature"])
    return f"{name}|{pubkey}|{signed_by}|{signature}"


def deserialize_cert(line):
    name, pubkey_str, signed_by, sig_str = line.split("|")
    if ',' in pubkey_str:
        e, n = map(int, pubkey_str.split(","))
        pubkey = (e, n)
    else:
        pubkey = int(pubkey_str)
    signature = int(sig_str)
    return {
        "name": name,
        "pubkey": pubkey,
        "signed_by": signed_by,
        "signature": signature
    }
#########################################################


p = 7919  # common prime number
g = 2     # generator

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ (key % 256) for b in data])


def start_server():
    global shared_key
    cert_chain, server_priv, _ = generate_certificate_chain()
    server_cert = cert_chain[0]  

    # step 1
    client_hello, client_addr = udp_socket.recvfrom(4096)
    client_hello = client_hello.decode()
    if not client_hello.startswith("ClientHello|"):
        return
    client_dh_pub = int(client_hello.split("|")[1])

    # step 2
    server_private = random.randint(100, 999)
    server_dh_pub = pow(g, server_private, p)
    sig = rsa_sign('ServerHello' + str(server_dh_pub), server_priv)

    # step 3
    hello_msg = f"ServerHello|{server_dh_pub}|MyServer|{sig}"
    cert_lines = [serialize_cert(c) for c in cert_chain]
    full_msg = "\n".join([hello_msg] + cert_lines)
    udp_socket.sendto(full_msg.encode(), client_addr)

    # step 4
    shared_key = pow(client_dh_pub, server_private, p)
    print("shared_key :", shared_key)
    return shared_key

TLS_1 = False
shared_key = None
############################



if len(sys.argv) < 2:
    print("Usage: python server.py <server_port>")
    sys.exit(1)
server_port = int(sys.argv[1])


credentials = {}
cred_file = "credentials.txt"
try:
    with open(cred_file, 'r') as cf:
        for line in cf:
            line = line.strip()
            if not line:
                continue
            # print(line)
            user, pwd = line.split()
            credentials[user] = pwd
except FileNotFoundError:
    open(cred_file, 'a').close()

# Online users
online_users = {}    # username -> address
online_addrs = {}    # address -> username

threads_list = []     # list of thread 
thread_owners = {}    # thread title -> creator username

pending_uploads = {}    # address -> (thread_title, filename, username)
pending_downloads = {}  # address -> (thread_title, filename, username)

# lock
cred_lock = threading.Lock()
user_lock = threading.Lock()
# thread_lock = threading.Lock()

thread_locks = {}
thread_locks_lock = Lock()

def get_thread_lock(threadname):
    with thread_locks_lock:
        if threadname not in thread_locks:
            thread_locks[threadname] = Lock()
        return thread_locks[threadname]

# udp
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(('127.0.0.1', server_port))
print("Waiting for clients")

# tcp
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind(('127.0.0.1', server_port))

online_zero_printed = False



client_queues = {} 

class UDPThread(Thread):
    def __init__(self, udp_socket, udp_address, msg_queue):
        Thread.__init__(self)
        self.udp_socket = udp_socket
        self.udp_address = udp_address
        self.msg_queue = msg_queue

        self.username = None
        self.log_in = False
        self.expecting_password = False
        self.message = None

    def login(self):
        if not self.expecting_password:
            self.name = self.message
            uname = self.message
            self.username = uname
            with cred_lock:
                user_exists = uname in credentials
            if user_exists:
                with user_lock:
                    already_online = uname in online_users
                if already_online:
                    self.udp_socket.sendto(f"{uname} has already logged in".encode(), self.udp_address)
                    print(f"{uname} has already logged in")
                    return

                else:
                    print('Client authenticating')
                    udp_socket.sendto("OK".encode(), self.udp_address)
                    self.is_new_user = False
                    self.expecting_password = True
            else:

                udp_socket.sendto("New user".encode(), self.udp_address)
                self.is_new_user = True
                self.expecting_password = True

        elif self.expecting_password:

            password = self.message
            uname = self.username
            if not self.is_new_user:
                with cred_lock:
                    stored_pwd = credentials.get(uname)
                if stored_pwd is None:

                    udp_socket.sendto("Invalid password".encode(), self.udp_address)
                    print("Incorrect password")
                    self.expecting_password = False
                elif password == stored_pwd:

                    with user_lock:
                        online_users[uname] = self.udp_address
                        online_addrs[self.udp_address] = uname
                    udp_socket.sendto("Welcome to the forum".encode(), self.udp_address)
                    print(f"{uname} successful login")
                    self.log_in = True
                else:
                    udp_socket.sendto("Invalid password".encode(), self.udp_address)
                    print("Incorrect password")
                    self.expecting_password = False
            else:
                with cred_lock:
                    credentials[uname] = password
                    with open(cred_file, 'a') as cf:
                        cf.write(f"{uname} {password}\n")
                with user_lock:
                    online_users[uname] = self.udp_address
                    online_addrs[self.udp_address] = uname
                udp_socket.sendto("Welcome to the forum".encode(), self.udp_address)
                print(f"{uname} successful logged in")
                self.log_in = True

    def crt(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) != 2:
            udp_socket.sendto("Incorrect syntax for CRT".encode(), client_addr)
        else:
            thread_title = parts[1]
            with get_thread_lock(thread_title):
                if thread_title in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} exists".encode(), client_addr)
                    print(f"{username} issued CRT command")
                    print(f"Thread {thread_title} exists")
                else:
                    open(thread_title, 'w').close()
                    threads_list.append(thread_title)
                    thread_owners[thread_title] = username
                    udp_socket.sendto(f"Thread {thread_title} created".encode(), client_addr)
                    print(f"{username} issued CRT command")
                    print(f"Thread {thread_title} created")

    def msg(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) < 3:
            udp_socket.sendto("Incorrect syntax for MSG".encode(), client_addr)
        else:
            thread_title = parts[1]
            message_text = " ".join(parts[2:])
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} not found".encode(), client_addr)
                    print(f"{username} issued MSG command")
                else:
                    lines = []
                    with open(thread_title, 'r') as tf:
                        lines = tf.readlines()
                    msg_num = 1
                    for line in lines:
                        if line.strip() == "":
                            continue
                        if line[0].isdigit():
                            try:
                                num = int(line.split()[0])
                                if num >= msg_num:
                                    msg_num = num + 1
                            except:
                                continue
                    with open(thread_title, 'a') as tf:
                        tf.write(f"{msg_num} {username}: {message_text}\n")
                    udp_socket.sendto(f"Message posted to {thread_title} thread".encode(), client_addr)
                    print(f"{username} issued MSG command")
                    print(f"Message posted to {thread_title} thread")
        

    def dlt(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) != 3:
            udp_socket.sendto("Incorrect syntax for DLT".encode(), client_addr)
        else:
            thread_title = parts[1]
            try:
                del_num = int(parts[2])
            except ValueError:
                udp_socket.sendto("Incorrect syntax for DLT".encode(), client_addr)
                print(f"{username} issued DLT command")
                return
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} not found".encode(), client_addr)
                else:
                    lines = []
                    with open(thread_title, 'r') as tf:
                        lines = tf.readlines()
                    msg_index = -1
                    msg_line = None
                    for idx, line in enumerate(lines):
                        if line.startswith(f"{del_num} "):
                            msg_index = idx
                            msg_line = line.strip()
                            break
                    if msg_index == -1:
                        udp_socket.sendto(f"Message {del_num} not found".encode(), client_addr)
                    else:
                        try:
                            msg_author = msg_line.split(' ', 1)[1].split(':')[0]
                        except Exception:
                            msg_author = None
                        if msg_author != username:
                            udp_socket.sendto("The message belongs to another user and cannot be deleted".encode(), client_addr)
                            print(f"{username} issued DLT command")
                            print("Message cannot be deleted")
                        else:
                            del lines[msg_index]
                            new_lines = []
                            msg_counter = 1
                            for line in lines:
                                if line.strip() == "":
                                    continue
                                if line[0].isdigit():
                                    content = line.strip().split(' ', 1)[1]
                                    new_lines.append(f"{msg_counter} {content}\n")
                                    msg_counter += 1
                                else:
                                    new_lines.append(line)
                            with open(thread_title, 'w') as tf:
                                tf.writelines(new_lines)
                            udp_socket.sendto(f"The message has been deleted".encode(), client_addr)
                            print(f"{username} issued DLT command")
                            print("Message has been deleted")
        

    def edt(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) < 4:
            udp_socket.sendto("Incorrect syntax for EDT".encode(), client_addr)
        else:
            thread_title = parts[1]
            try:
                edit_num = int(parts[2])
            except ValueError:
                udp_socket.sendto("Incorrect syntax for EDT".encode(), client_addr)
                print(f"{username} issued EDT command")
                return
            new_message = " ".join(parts[3:])
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} not found".encode(), client_addr)
                else:
                    lines = []
                    with open(thread_title, 'r') as tf:
                        lines = tf.readlines()
                    msg_index = -1
                    msg_line = None
                    for idx, line in enumerate(lines):
                        if line.startswith(f"{edit_num} "):
                            msg_index = idx
                            msg_line = line.strip()
                            break
                    if msg_index == -1:
                        udp_socket.sendto(f"Message {edit_num} not found".encode(), client_addr)
                    else:
                        try:
                            msg_author = msg_line.split(' ', 1)[1].split(':')[0]
                        except Exception:
                            msg_author = None
                        if msg_author != username:
                            udp_socket.sendto("The message belongs to another user and cannot be edited".encode(), client_addr)
                        else:
                            lines[msg_index] = f"{edit_num} {username}: {new_message}\n"
                            with open(thread_title, 'w') as tf:
                                tf.writelines(lines)
                            udp_socket.sendto(f"Message {edit_num} edited".encode(), client_addr)
        print(f"{username} issued EDT command")

    def lst(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) != 1:
            udp_socket.sendto("Incorrect syntax for LST".encode(), client_addr)
        else:
            if len(threads_list) == 0:
                udp_socket.sendto("No threads to list".encode(), client_addr)
            else:
                response = "The list of active threads:\n"
                response += "\n".join(threads_list)
                udp_socket.sendto(response.encode(), client_addr)
        print(f"{username} issued LST command")

    def rdt(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) != 2:
            udp_socket.sendto("Incorrect syntax for RDT".encode(), client_addr)
        else:
            thread_title = parts[1]
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} does not exist".encode(), client_addr)
                    print(f"{username} issued RDT command")
                    print(f"Incorrect thread specified")
                else:
                    lines = []
                    with open(thread_title, 'r') as tf:
                        lines = [ln.rstrip() for ln in tf]
                    if not lines or all(ln.strip() == "" for ln in lines):
                        udp_socket.sendto(f"Thread {thread_title} is empty".encode(), client_addr)
                    else:
                        content = "\n".join([ln for ln in lines if ln.strip() != ""])
                        udp_socket.sendto(content.encode(), client_addr)
                    
                    print(f"{username} issued RDT command")
                    print(f"Thread {thread_title} read")
                
    def rmv(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) != 2:
            udp_socket.sendto("Incorrect syntax for RMV".encode(), client_addr)
        else:
            thread_title = parts[1]
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} not found".encode(), client_addr)
                else:
                    if thread_owners.get(thread_title) != username:
                        udp_socket.sendto("Thread cannot be removed".encode(), client_addr)
                        print(f"{username} issued RMV command")
                        print(f"Thread {thread_title} cannot be removed")
                    else:
                        try:
                            with open(thread_title, 'r') as tf:
                                tlines = tf.readlines()
                            for ln in tlines:
                                if " uploaded " in ln:
                                    file_name = ln.split(" uploaded ", 1)[1].strip()
                                    try:
                                        os.remove(file_name)
                                    except:
                                        pass
                        except FileNotFoundError:
                            pass
                        try:
                            os.remove(thread_title)
                        except:
                            pass
                        threads_list.remove(thread_title)
                        thread_owners.pop(thread_title, None)
                        udp_socket.sendto(f"Thread removed".encode(), client_addr)
                        print(f"{username} issued RMV command")
                        print(f"Thread {thread_title} removed")
        

    def xit(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username

        if username in online_users:
            with user_lock:
                online_users.pop(username, None)
                online_addrs.pop(client_addr, None)
        print(f"{username} exited")
        udp_socket.sendto(f"GZH".encode(), client_addr)
        global online_zero_printed
        if len(online_users) == 0 and not online_zero_printed:
            print("Waiting for clients")
            online_zero_printed = True
        elif len(online_users) > 0:
            online_zero_printed = False

    def upd(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username

        if len(parts) != 3:
            udp_socket.sendto("Incorrect syntax for UPD".encode(), client_addr)
        else:
            thread_title = parts[1]
            file_name = parts[2]
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    udp_socket.sendto(f"Thread {thread_title} not found".encode(), client_addr)
                else:
                    if os.path.exists(file_name):
                        udp_socket.sendto("File already exists".encode(), client_addr)
                    else:
                        pending_uploads[client_addr] = (thread_title, file_name, username)
                        udp_socket.sendto("READY".encode(), client_addr)
        print(f"{username} issued UPD command")

    def dwn(self):
        parts = self.message.split()
        client_addr = self.udp_address
        username = self.username
        if len(parts) != 3:
            udp_socket.sendto("Incorrect syntax for DWN".encode(), client_addr)
        else:
            thread_title = parts[1]
            file_name = parts[2]
            with get_thread_lock(thread_title):
                if thread_title not in threads_list:
                    print(f"{username} issued DWN command")
                    udp_socket.sendto(f"Thread {thread_title} not found".encode(), client_addr)
                else:
                    if not os.path.exists(file_name):
                        print(f"{username} issued DWN command")
                        print(f"{file_name} does not exist in Thread {thread_title}")
                        udp_socket.sendto(f"{file_name} does not exist in Thread {thread_title}".encode(), client_addr)
                    else:
                        file_in_thread = False
                        with open(thread_title, 'r') as tf:
                            for ln in tf:
                                if f" uploaded {file_name}" in ln:
                                    file_in_thread = True
                                    break
                        if not file_in_thread:
                            print(f"{username} issued DWN command")
                            print(f"{file_name} does not exist in Thread {thread_title}")
                            udp_socket.sendto(f"File does not exist in Thread {thread_title}".encode(), client_addr)
                        else:
                            pending_downloads[client_addr] = (thread_title, file_name, username)
                            print(f"{username} issued DWN command")
                            udp_socket.sendto("READY".encode(), client_addr)

        

    def run(self):
        while True:
            self.message = self.msg_queue.get().decode()
            parts = self.message.split()
            client_addr = self.udp_address
            username = self.username
            if not self.log_in:
                self.login()
            else:
                parts = self.message.split()
                if len(parts) == 0:
                    continue
                command = parts[0]
                if command == "CRT":
                    self.crt()
                elif command == "MSG":
                    self.msg()
                elif command == "DLT":
                    self.dlt()
                elif command == "EDT":
                    self.edt()
                elif command == "LST":
                    self.lst()
                elif command == "RDT":
                    self.rdt()
                elif command == "RMV":
                    self.rmv()
                elif command == "XIT":
                    self.xit()
                    break
                elif command == "UPD":
                    self.upd()
                elif command == "DWN":
                    self.dwn()
                else:
                # unrecognized command
                    udp_socket.sendto("Invalid command".encode(), client_addr)
                    # print(f"{username} issued invalid command")                
        client_queues.pop(client_addr, None)


class TCPThread(Thread):
    def __init__(self, tcp_socket, tcp_address, connect):
        Thread.__init__(self)
        self.tcp_socket = tcp_socket
        self.tcp_address = tcp_address
        self.connect = connect



    def run(self):
        tcp_socket = self.tcp_socket
        tcp_address = self.tcp_address
        connect = self.connect
        client_ip = self.tcp_address[0]
        # print(self.tcp_address)
        # print(self.tcp_address[0])

        upload_key = None
        download_key = None

        for key in pending_uploads:
            if key[0] == client_ip:
                upload_key = key
                break
        if upload_key is None:
            for key in pending_downloads:
                if key[0] == client_ip:
                    download_key = key
                    break

        if upload_key:
            thread_title, filename, username = pending_uploads.pop(upload_key)

            with open(filename, 'wb') as f:
                while True:
                    data = connect.recv(4096)
                    if not data:
                        break
                    f.write(data)
            connect.close()

            with get_thread_lock(thread_title):
                with open(thread_title, 'a') as tf:
                    tf.write(f"{username} uploaded {filename}\n")

            udp_socket.sendto(f"{filename} uploaded to {thread_title} thread".encode(), upload_key)
            print(f"{username} uploaded file {filename} to {thread_title} thread")

        elif download_key:

            thread_title, filename, username = pending_downloads.pop(download_key)
            try:
                with open(filename, 'rb') as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        connect.sendall(chunk)
            except FileNotFoundError:
                pass
            connect.close()
            udp_socket.sendto(f"{filename} successfully downloaded".encode(), download_key)
            print(f"{filename} downloaded from Thread {thread_title}")

        else:

            connect.close()

def udp_loop():
    while True:
        data, addr = udp_socket.recvfrom(4096)
        if addr not in client_queues:
            # print(addr)

            msg_q = Queue()
            client_queues[addr] = msg_q
            udp_thread = UDPThread(udp_socket, addr, msg_q)
            udp_thread.start()

        client_queues[addr].put(data)

    

def tcp_loop():
    tcp_socket.listen(5)
    while True:
        connect, addr = tcp_socket.accept()
        # print(connect)
        clientThread = TCPThread(tcp_socket, addr ,connect)
        clientThread.start()

    
def main():
    if TLS_1:
        start_server()

    threading.Thread(target = udp_loop, daemon = True).start()
    threading.Thread(target = tcp_loop, daemon = True).start()


    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Server shutting down")

if __name__ == '__main__':
    main()