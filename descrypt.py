from cryptography.fernet import Fernet

aes_key = b"4ixLmTMUfiCDGXNDvdQCEUrKl5f3QWLr-cTlKBttXHY="

cipher = Fernet(aes_key)

encrypted_message = b"gAAAAABntzff0UJxPE2nvarz0Hn-Vfd_NTEAzPK4cCRCOAgv9WYYBNMppXS5FxbS1Hu3sypKMM8ZCT1rmB8rtWIbiJxE1kDWfL1I46aEEr-7GOiPIDEPVrVDoOjQIDVsqg-bRRVaIjqZttLvvOZPaahtTxPKRwrD7z1EWB4aTPl8M8AIxh7OVpQXpV3C5ZaqmhdWlb9Oxz2XqxExMQNx72EVRm1E42Dh793janWt5KPnnSae-KgWVpQ="

decrypted_message = cipher.decrypt(encrypted_message).decode()

print(f"Mensagem descriptografada: {decrypted_message}")
