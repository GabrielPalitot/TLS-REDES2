import socket
import threading
import uuid
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)

client_keys = {}

def handle_client(conn, addr):
    print(f"[+] Cliente {addr} conectado.")
    
    conn.send(public_pem)
    
    encrypted_aes_key = conn.recv(1024)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    
    cipher = Fernet(aes_key)
    client_keys[addr] = cipher
    
    while True:
        try:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                break
            
            decrypted_message = cipher.decrypt(encrypted_data).decode()
            
            nonce, mac, message = decrypted_message.split("|")
            
            computed_mac = hmac.new(aes_key, f"{nonce}|{message}".encode(), hashlib.sha256).hexdigest()
            if computed_mac != mac:
                print(f"[ALERTA] Mensagem alterada em trânsito! {addr}")
                continue
            
            print(f"({addr}) {message}")
        except Exception as e:
            print(f"[!] Erro ao processar mensagem: {e}")
            break
    
    conn.close()
    print(f"[-] Cliente {addr} desconectado.")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9000))
server.listen(5)

print("Servidor aguardando conexões...")

while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()
