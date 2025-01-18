import socket
import secrets

# Параметры протокола
P = 23  # Простое число
G = 5   # Генератор

def diffie_hellman_server():
    server_private_key = secrets.randbelow(P)
    server_public_key = pow(G, server_private_key, P)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', 65432))
        server_socket.listen(1)
        print("Сервер запущен, ожидается подключение...")

        client_socket, addr = server_socket.accept()
        with client_socket:
            print(f"Клиент подключился: {addr}")

            # Получение открытого ключа клиента
            client_public_key = int(client_socket.recv(1024).decode('utf-8'))
            print(f"Открытый ключ клиента: {client_public_key}")

            # Отправка серверного открытого ключа
            client_socket.sendall(str(server_public_key).encode('utf-8'))
            print(f"Открытый ключ сервера отправлен: {server_public_key}")

            # Вычисление общего ключа
            shared_key = pow(client_public_key, server_private_key, P)
            print(f"Общий ключ: {shared_key}")

if __name__ == "__main__":
    diffie_hellman_server()
