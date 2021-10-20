from __future__ import annotations

import socket
import time
from crypto_utils import *
from config import *


def encrypt_message_with_mode(mode, message, K):
    mode_class : BaseMode = None
    if mode == ECB:
        mode_class = Mode_ECB(K)
    elif mode == OFB:
        mode_class = Mode_OFB(K, IV)
    print(f"Mesajul care trebuie encriptat: {message}\n")
    print(f"Modul folosit pentru encriptarea mesajului: {mode_class.ID}\n")
    encrypted_msg = mode_class.encrypt(message)
    return encrypted_msg


def request_from_key_manager(mode):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as kms:
        kms.connect((HOST, PORT_KM))
        # se conecteaza la key manager si ii trimite modul de operatie
        kms.sendall(mode.encode())
        
        # preia cheia encriptata de la key manager
        K_encrypted = kms.recv(16)
        print(f"Cheia primita de la nodul KM: {K_encrypted}\n")
        
        #decripteaza cheia
        K = decrypt_128bit(K_encrypted, K_PRIM)
        print(f"Cheia decriptata: {K}\n")
        return K, K_encrypted
    
    
def send_encrypted_file_to(sock: socket.socket, mode, K):
    file_name = input("Numele fisierului pe care vreti sa-l trimiteti: ")
    try:
        with open(file_name, "rb") as f:
            file_text = f.read()
            
            encrypted_message = encrypt_message_with_mode(mode, file_text, K)
            
            file_size = len(encrypted_message)

            sock.sendall(file_size.to_bytes(4, 'big'))
            print(f"Mesajul encriptat: {encrypted_message}")
            sock.sendall(encrypted_message)
    except FileNotFoundError:
        print("Nu s-a gasit fisierul, incercati din nou.")
        send_encrypted_file_to(sock, mode, K)
    
    
def connect_with_B(mode, K, K_encrypted):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT_B))
        
        # trimite modul de operatie catre nodul B impreuna cu cheia encriptata
        s.sendall(mode.encode())
        s.sendall(K_encrypted)
        
        # primeste semnalul de start de la nodul B
        start_signal = s.recv(5)
        print(f'Semnalul a fost primit de la B: {start_signal.decode()}\n')
        
        # trimite fisierul/mesajul encriptat catre nodul B
        send_encrypted_file_to(s, mode, K)
        

if __name__ == "__main__":
    op_mode = input("Ce mod doriti sa folositi: \n1. ECB\n2. OFB\n>> ")
    op_mode = ECB if op_mode == "1" else OFB
    
    K, K_encrypted = request_from_key_manager(op_mode)
    
    connect_with_B(op_mode, K, K_encrypted)