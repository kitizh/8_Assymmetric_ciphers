import socket
import secrets

# Параметры протокола
P = 23  # Простое число
G = 5   # Генератор

def diffie_hellman_client():
    client_private_key = secrets.randbelow(P)
    client_public_key = pow(G, client_private_key, P)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('127.0.0.1', 65432))
        print("Подключение к серверу установлено.")

        # Отправка клиентского открытого ключа
        client_socket.sendall(str(client_public_key).encode('utf-8'))
        print(f"Открытый ключ клиента отправлен: {client_public_key}")

        # Получение серверного открытого ключа
        server_public_key = int(client_socket.recv(1024).decode('utf-8'))
        print(f"Открытый ключ сервера: {server_public_key}")

        # Вычисление общего ключа
        shared_key = pow(server_public_key, client_private_key, P)
        print(f"Общий ключ: {shared_key}")

if __name__ == "__main__":
    diffie_hellman_client()
