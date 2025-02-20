import hashlib
import socket
import uuid
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def test_tampered_message():
    # Conectar ao servidor
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9000))
    
    # Receber a chave pública do servidor
    public_pem = client.recv(1024)
    public_key = serialization.load_pem_public_key(public_pem)
    
    # Criar e enviar chave AES legítima
    aes_key = Fernet.generate_key()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client.send(encrypted_aes_key)
    
    # Criar mensagem maliciosa com MAC inválido
    nonce = str(uuid.uuid4())
    fake_mac = "fake_mac_" * 8  # MAC com tamanho similar ao real
    message = "Mensagem adulterada"
    
    tampered_message = f"{nonce}|{fake_mac}|{message}"
    cipher = Fernet(aes_key)
    encrypted_message = cipher.encrypt(tampered_message.encode())
    
    # Enviar mensagem adulterada
    client.send(encrypted_message)
    
    # Aguardar e descriptografar resposta do servidor
    try:
        encrypted_response = client.recv(1024)
        decrypted_response = cipher.decrypt(encrypted_response).decode()
        
        # Extrair componentes da mensagem
        nonce, mac, message = decrypted_response.split("|")
        
        print("\n[TEST] Resposta do servidor após tentativa de adulteração:")
        print(f"- Mensagem recebida: {message}")
        print("[TEST] Simulação de ataque concluída")
            
    except Exception as e:
        print(f"\n[!] Erro ao processar resposta: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    test_tampered_message()