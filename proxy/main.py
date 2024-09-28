import gzip
import json
import select
import socket
import zlib
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

#import psycopg2
import ssl
import threading
import os
import subprocess

PROXY_PORT = 8080

# Путь к корневому сертификату и ключу
CA_CERT = "certs/ca.pem"
CA_KEY = "certs/ca.key"


def generate_cert(hostname):
    cert_file = f"certs/{hostname}.crt"
    key_file = f"certs/{hostname}.key"

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        # Генерируем ключ для хоста
        subprocess.run(["openssl", "genrsa", "-out", key_file, "2048"])

        # Создаем CSR (запрос на подпись сертификата)
        subprocess.run(["openssl", "req", "-new", "-key", key_file, "-out", f"{hostname}.csr",
                        "-subj", f"/C=RU/ST=Moscow/L=Moscow/O=MyProxy/CN={hostname}"])

        # Подписываем сертификат корневым CA
        subprocess.run(["openssl", "x509", "-req", "-in", f"{hostname}.csr", "-CA", CA_CERT, "-CAkey", CA_KEY,
                        "-CAcreateserial", "-out", cert_file, "-days", "365", "-sha256"])

    return cert_file, key_file


def handle_http(client_socket, request):
    try:
        # Получаем первую строку запроса
        first_line = request.split('\n')[0]
        method, url, http_version = first_line.split()

        # Убираем "http://", если есть, и парсим хост и путь
        if url.startswith("http://"):
            url = url[len("http://"):]

        # Разбиваем хост и путь
        if '/' in url:
            host, path = url.split('/', 1)
            path = '/' + path  # Добавляем '/' перед путем
        else:
            host = url
            path = '/'

        # Проверяем наличие порта
        if ':' in host:
            host, port = host.split(':')
            port = int(port)
        else:
            port = 80  # По умолчанию порт 80 для HTTP

        # Убираем заголовок Proxy-Connection
        headers = request.split('\r\n')[1:]
        headers= headers[:len(headers)-2]
        headers = [line for line in headers if not line.startswith("Proxy-Connection")]

        # Формируем новый запрос
        new_request = f"{method} {path} {http_version}\r\n" + '\r\n'.join(headers) + '\r\n\r\n'

        print(f"[*] Проксируем запрос к {host}:{port}")

        # Создаем сокет для подключения к целевому серверу
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((host, port))
        target_socket.setblocking(False)

        target_socket.sendall(new_request.encode())

        response = b""
        try:
            while True:
                ready_to_read, _, _ = select.select([target_socket], [], [], 1.0)
                if ready_to_read:
                    data = target_socket.recv(4096)
                    if not data:
                        break
                    response += data
                else:
                    break
        except socket.error as e:
            print(f"Ошибка сокета: {e}")
        finally:
            target_socket.close()

        # Логируем и сохраняем запрос и ответ в базе данных (если требуется)
        header_data, _, body_data = response.partition(b'\r\n\r\n')
        response_headers = header_data.decode('utf-8', errors='ignore').split('\r\n')
        #response_headers_list = response_headers.split('\r\n')

        response_body = body_data.decode('utf-8', errors='ignore')


        # Сохраняем запрос и ответ в базу данных (если требуется)
        print(host,port,new_request,response_headers,response_body)
        #request_id = save_request(host, port, new_request, None)
        #save_response(request_id, response_headers, response_body)
        # Отправляем ответ клиенту
        if response:
            client_socket.sendall(response)
        else:
            print("Сервер не вернул данных.")
    except Exception as e:
        print(f"Ошибка при обработке HTTP-запроса: {e}")
    finally:
        client_socket.close()


def handle_client(client_socket):
    try:
        request = client_socket.recv(2048).decode('utf-8')

        if request.startswith("CONNECT"):
            pass
            #Обрабатываем HTTPS (CONNECT-запрос)
            #handle_https(client_socket, request)
        else:
            # Обрабатываем обычный HTTP-запрос
            handle_http(client_socket, request)

    except Exception as e:
        print(f"Ошибка: {e}")
        client_socket.close()

def start_proxy():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', PROXY_PORT))
    server_socket.listen(5)

    print(f"[*] Прокси сервер запущен на порту {PROXY_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[*] Получено соединение от {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    #init_db()
    #init_db()
    start_proxy()