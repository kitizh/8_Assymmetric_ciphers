import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def rsa_client():
    # Генерация пары ключей
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('127.0.0.1', 65432))
        print("Подключение к серверу установлено.")

        # Отправка клиентского открытого ключа
        client_public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(client_public_key_pem)
        print("Открытый ключ клиента отправлен.")

        # Получение серверного открытого ключа
        server_public_key_pem = client_socket.recv(4096)
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)
        print("Открытый ключ сервера получен.", server_public_key_pem)

        # Шифрование и отправка сообщения
        message = "Привет, сервер!".encode('utf-8')
        encrypted_message = server_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_socket.sendall(encrypted_message)
        print("Сообщение отправлено серверу.")

if __name__ == "__main__":
    rsa_client()
