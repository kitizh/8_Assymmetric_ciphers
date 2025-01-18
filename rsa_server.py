import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def rsa_server():
    # Генерация пары ключей
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', 65432))
        server_socket.listen(1)
        print("Сервер запущен, ожидается подключение...")

        client_socket, addr = server_socket.accept()
        with client_socket:
            print(f"Клиент подключился: {addr}")

            # Получение клиентского открытого ключа
            client_public_key_pem = client_socket.recv(4096)
            client_public_key = serialization.load_pem_public_key(client_public_key_pem)
            print("Открытый ключ клиента получен.", client_public_key_pem)

            # Отправка серверного открытого ключа
            server_public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.sendall(server_public_key_pem)
            print("Открытый ключ сервера отправлен.")

            # Прием и расшифровка сообщения
            encrypted_message = client_socket.recv(4096)
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"Сообщение от клиента: {decrypted_message.decode('utf-8')}")

if __name__ == "__main__":
    rsa_server()
