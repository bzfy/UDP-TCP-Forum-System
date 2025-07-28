import socket, sys
import socket
import random
from socket import *

# ca_pool
TRUSTED_CAS = {
    "RootCA": (17, 3233),  # root certificate
    "BackupCA": (13, 187)
}


# tls_utility
######################################
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

############################################





p = 7919  # 公共素数
g = 2     # generator

def xor_encrypt_decrypt(data, key):
    return bytes([b ^ (key % 256) for b in data])



def verify_chain(cert_lines):
    certs = [deserialize_cert(line) for line in cert_lines]
    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer = certs[i + 1]
        msg = cert["name"] + str(cert["pubkey"])

        if not rsa_verify(msg, cert["signature"], issuer["pubkey"]):
            return False, f"error: {cert['name']} ← {issuer['name']}"

    root = certs[-1]
    msg = root["name"] + str(root["pubkey"])
    if not rsa_verify(msg, root["signature"], root["pubkey"]):
        return False, "root cd dont self sign"

    if root["name"] not in TRUSTED_CAS:
        return False, "root ca not in pool"
    if root["pubkey"] != TRUSTED_CAS[root["name"]]:
        return False, "root ca not ok"

    return True, "ok"

def start_client():
    global shared_key

    # step 1
    client_private = random.randint(100, 999)
    client_dh_pub = pow(g, client_private, p)
    hello_msg = f"ClientHello|{client_dh_pub}"
    udp_socket.sendto(hello_msg.encode(), server_address)

    # step 2
    data, _ = udp_socket.recvfrom(4096)
    lines = data.decode().strip().split("\n")
    server_dh_line = lines[0]
    cert_lines = lines[1:]

    ok, msg = verify_chain(lines)
    print("error:", msg)
    if not ok:
        return

    # step 3
    server_dh_pub = int(server_dh_line.split("|")[1])
    shared_key = pow(server_dh_pub, client_private, p)
    print("shared_key :", shared_key)
    return shared_key


TLS_1 = False
shared_key = None
##############################






if len(sys.argv) < 2:
    print("Usage: python client.py <server_port>")
    sys.exit(1)
server_port = int(sys.argv[1])
server_host = "127.0.0.1"  
server_address = (server_host, server_port)


udp_socket = socket(AF_INET, SOCK_DGRAM)
tcp_socket = socket(AF_INET, SOCK_STREAM)
BUFFER_SIZE = 4096

clientAlive = True
Retransmission = True

def udp_send(msg, retries=3, timeout=3):
    udp_socket.settimeout(timeout)
    for attempt in range(retries):
        try:
            udp_socket.sendto(msg.encode(), server_address)
            response = udp_socket.recvfrom(BUFFER_SIZE)[0].decode()
            return response
        except socket.timeout:
            print(f"Timeout waiting for server (attempt {attempt+1}/{retries})")
        except Exception as e:
            print(f"Other error: {e}")
    return "ERROR: No response from server"




def display_menu():
    """
    Display the available commands
    """
    print("\n===== Available Commands =====")
    print("1. CRT threadtitle")
    print("2. MSG thread message")
    print("3. DLT thread messagenumber")
    print("4. EDT threadtitle messagenumber message")
    print("5. LST")
    print("6. RDT threadtitle")
    print("7. RMV threadtitle")
    print("8. XIT")
    print("9. UPD threadtitle filename")
    print("10. DWN threadtitle filename")
    print("================================\n")

def parse_user_input(command):
    global clientAlive
    if command.strip() == "":
        return
    parts = command.split()
    parts[0] = parts[0].upper()
    command = ' '.join(parts)
    cmd = parts[0].upper()

    if cmd == "CRT":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "MSG":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "DLT":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "EDT":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "LST":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "RDT":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "RMV":
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)
    elif cmd == "XIT":
        if Retransmission:
            resp_msg = udp_send(command)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
        if resp_msg == 'GZH':
            clientAlive = False
            print("Goodbye")
            return 
    elif cmd == "UPD":
        if len(parts) != 3:
            print("Usage: UPD <threadtitle> <filename>")
            return
        thread_title = parts[1]
        filename = parts[2]
        try:
            with open(filename, "rb") as f:
                pass
        except FileNotFoundError:
            print("File not found")
            return
        
        if Retransmission:
            resp_msg = udp_send(command)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()

        if resp_msg == "READY":
            tcp_socket.connect(server_address)
            with open(filename, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    tcp_socket.sendall(chunk)
            tcp_socket.close()
            final_resp, addr_final = udp_socket.recvfrom(4096)
            print(final_resp.decode())
        else:
            print(resp_msg)
        return
    elif cmd == "DWN":
        if len(parts) != 3:
            print("Usage: DWN <threadtitle> <filename>")
            return
        thread_title = parts[1]
        filename = parts[2]

        if Retransmission:
            resp_msg = udp_send(command)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()


        if resp_msg == "READY":       
            tcp_socket.connect(server_address)
            with open(filename, "wb") as f:
                while True:
                    data = tcp_socket.recv(4096)
                    if not data:
                        break
                    f.write(data)
            tcp_socket.close()
            final_resp, addr_final = udp_socket.recvfrom(4096)
            print(final_resp.decode())
        else:
            print(resp_msg)
        return
    elif cmd == 'HELP':
        display_menu()
    else:
        if Retransmission:
            resp_msg = udp_send(command)
            print(resp_msg)
        else:
            udp_socket.sendto(command.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE) 
            resp_msg = resp.decode()
            print(resp_msg)



def login():
    while True:
        username = input("Enter username: ")
        if Retransmission:
            resp_decoded = udp_send(username)
        else:
            udp_socket.sendto(username.encode(), server_address)
            resp, addr = udp_socket.recvfrom(BUFFER_SIZE)
            resp_decoded = resp.decode()


        if resp_decoded.startswith("OK"):

            password = input("Enter password: ")

            if Retransmission:

                result_msg = udp_send(password)
                print(result_msg)
            else:
                udp_socket.sendto(password.encode(), server_address)
                result, addr2 = udp_socket.recvfrom(BUFFER_SIZE)
                result_msg = result.decode()
                print(result_msg)


            if result_msg == "Welcome to the forum":

                break
            else:
                continue

        elif resp_decoded == "New user":
            print(resp_decoded) 
            password = input("Enter new password: ")
            if Retransmission:
                result_msg = udp_send(password)
                print(result_msg)
            else:
                udp_socket.sendto(password.encode(), server_address)
                result, addr2 = udp_socket.recvfrom(BUFFER_SIZE)
                result_msg = result.decode()
                print(result_msg)
            if result_msg == "Welcome to the forum":
                break
            else:
                continue
        else:
            print(resp_decoded)
            continue

def main():
    global clientAlive

    if TLS_1:
        start_client()

    try:
        login()
        while clientAlive:
            command = input("Enter one of the following commands: CRT, MSG, DLT, EDT, LST, RDT, UPD, DWN, RMV, XIT: ")
            parse_user_input(command)
    except KeyboardInterrupt:
        print("Client shutting down.")




if __name__ == '__main__':
    main()