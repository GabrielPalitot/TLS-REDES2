import socket
import uuid
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 9000))

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

threading.Thread(target=send_message).start()
