import socket
import uuid
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 9000))

public_pem = client.recv(1024)
public_key = serialization.load_pem_public_key(public_pem)

aes_key = Fernet.generate_key()

encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None)
)
client.send(encrypted_aes_key)

cipher = Fernet(aes_key)

def send_message():
    while True:
        message = input("Digite: ")
        
        nonce = str(uuid.uuid4())
        
        mac = hmac.new(aes_key, f"{nonce}|{message}".encode(), hashlib.sha256).hexdigest()
        
        authenticated_message = f"{nonce}|{mac}|{message}"
        
        encrypted_message = cipher.encrypt(authenticated_message.encode())
        client.send(encrypted_message)

def receive_messages():
    while True:
        try:
            encrypted_message = client.recv(1024)
            message = cipher.decrypt(encrypted_message).decode()
            
            nonce, mac, content = message.split("|")
            
            computed_mac = hmac.new(
                cipher._signing_key,
                f"{nonce}|{content}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if hmac.compare_digest(mac, computed_mac):
                print(f"\n[✓] Mensagem autenticada: {content}")
                print("Digite: ", end='', flush=True)
            else:
                print("\n[❌] ALERTA: Mensagem não autenticada detectada!")
                print(f"[❌] Conteúdo suspeito: {content}")
                # Notificar servidor sobre tentativa de adulteração
                alert_message = f"ALERT|{nonce}|Mensagem não autenticada detectada"
                encrypted_alert = cipher.encrypt(alert_message.encode())
                client.send(encrypted_alert)
                print("Digite: ", end='', flush=True)
        except Exception as e:
            print(f"\n[!] Erro ao receber mensagem: {e}")

threading.Thread(target=send_message).start()
threading.Thread(target=receive_messages).start()
