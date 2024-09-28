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
CA_CERT = "certs/ca.crt"
CA_KEY = "certs/ca.key"


def generate_cert(hostname):
    cert_file = f"certs/{hostname}.crt"
    key_file = f"certs/{hostname}.key"

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        # Генерируем ключ для хоста
        subprocess.run(["openssl", "genrsa", "-out", key_file, "2048"])

        # Создаем CSR (запрос на подпись сертификата)
        csr_file = f"certs/{hostname}.csr"  # Создаем CSR в папке certs
        subprocess.run(["openssl", "req", "-new", "-key", key_file, "-out", csr_file,
                        "-subj", f"/C=RU/ST=Moscow/L=Moscow/O=MyProxy/CN={hostname}"])

        # Подписываем сертификат корневым CA
        subprocess.run(["openssl", "x509", "-req", "-in", csr_file, "-CA", CA_CERT, "-CAkey", CA_KEY,
                        "-CAcreateserial", "-out", cert_file, "-days", "365", "-sha256"])

    return cert_file, key_file

def decompress_content(data, encoding):
    try:
        if encoding == 'gzip':
            return gzip.decompress(data).decode('utf-8', errors='ignore')
        elif encoding == 'deflate':
            return zlib.decompress(data).decode('utf-8', errors='ignore')
        else:
            return data.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Ошибка декомпрессии: {e}")
        return data.decode('utf-8', errors='ignore')


def parse_http_request(request_str):
    request_lines = request_str.split('\r\n')
    first_line = request_lines[0]
    method, full_path, http_version = first_line.split()

    # Парсим URL и GET параметры
    parsed_url = urlparse(full_path)
    path = parsed_url.path
    get_params = parse_qs(parsed_url.query)

    # Парсим заголовки
    headers = {}
    cookies = {}
    for line in request_lines[1:]:
        if ': ' in line:
            header_name, header_value = line.split(': ', 1)
            headers[header_name] = header_value
            if header_name == 'Cookie':
                cookie = SimpleCookie()
                cookie.load(header_value)
                cookies = {k: v.value for k, v in cookie.items()}

    # Логируем заголовки и Cookie
    print(f"Headers: {headers}")
    print(f"Cookies: {cookies}")

    # Возвращаем результат парсинга
    return {
        "method": method,
        "path": path,
        "get_params": get_params,
        "headers": headers,
        "cookies": cookies
    }


def parse_post_body(body, headers):
    post_params = {}
    if "Content-Type" in headers and headers["Content-Type"] == "application/x-www-form-urlencoded":
        post_params = parse_qs(body)
    return post_params


def parse_http_response(response_str, response_body):
    response_lines = response_str.split('\r\n')
    first_line = response_lines[0]
    http_version, status_code, status_message = first_line.split(' ', 2)

    headers = {}
    for line in response_lines[1:]:
        if ': ' in line:
            header_name, header_value = line.split(': ', 1)
            headers[header_name] = header_value

    # Проверяем сжатие ответа и декомпрессируем
    if 'Content-Encoding' in headers:
        response_body = decompress_content(response_body, headers['Content-Encoding'])

    # Логируем заголовки и тело ответа
    print(f"Response Code: {status_code}")
    print(f"Headers: {headers}")
    print(f"Body: {response_body[:200]}...")  # Обрезаем тело для логирования

    return {
        "code": status_code,
        "message": status_message,
        "headers": headers,
        "body": response_body
    }

def handle_http(client_socket, request):
    try:
        # Получаем первую строку запроса
        first_line = request.split('\n')[0]
        method, url, http_version = first_line.split()

        # Убираем "http://", если есть, и парсим хост и путь
        if url.startswith("http://"):
            url = url[len("http://"):]

        if '/' in url:
            host, path = url.split('/', 1)
            path = '/' + path  # Добавляем '/' перед путем
        else:
            host = url
            path = '/'

        port = 80  # По умолчанию порт 80 для HTTP
        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        # Убираем заголовок Proxy-Connection
        headers = request.split('\r\n')[1:]
        headers = headers[:len(headers)-2]
        headers = [line for line in headers if not line.startswith("Proxy-Connection")]

        new_request = f"{method} {path} {http_version}\r\n" + '\r\n'.join(headers) + '\r\n\r\n'
        print(f"[*] Проксируем запрос к {host}:{port}")

        # Парсим запрос
        parsed_request = parse_http_request(new_request)
        print(parsed_request)

        # Подключаемся к целевому серверу
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((host, port))
        target_socket.sendall(new_request.encode())

        response = b""
        while True:
            data = target_socket.recv(4096)
            if not data:
                break
            response += data

        # Обработка ответа
        response_str, _, response_body = response.partition(b'\r\n\r\n')
        response_headers_str = response_str.decode('utf-8', errors='ignore')
        response_body_str = decompress_content(response_body, headers.get('Content-Encoding', ''))

        # Парсим ответ
        parsed_response = parse_http_response(response_headers_str, response_body_str)
        print(parsed_response)

        # Отправляем ответ клиенту
        if response:
            client_socket.sendall(response)
        else:
            print("Сервер не вернул данных.")
    except Exception as e:
        print(f"Ошибка при обработке HTTP-запроса: {e}")
    finally:
        client_socket.close()


def forward_data(src, dest, is_request):
    data = b""
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            dest.sendall(chunk)
            data += chunk
    except Exception as e:
        print(f"Error during forwarding: {e}")
    finally:
        src.close()
        dest.close()

    # Если это запрос (is_request=True)
    if is_request:
        try:
            request_str = data.decode('utf-8', errors='ignore')
            parsed_request = parse_http_request(request_str)
            print(parsed_request)
        except Exception as e:
            print(f"Ошибка при разборе HTTPS-запроса: {e}")
    # Если это ответ (is_request=False)
    else:
        try:
            response_str, _, response_body = data.partition(b'\r\n\r\n')
            response_headers_str = response_str.decode('utf-8', errors='ignore')
            parsed_response = parse_http_response(response_headers_str, response_body)
            print(parsed_response)
        except Exception as e:
            print(f"Ошибка при разборе HTTPS-ответа: {e}")


def handle_https(client_socket, request):
    try:
        # Получаем хост и порт из CONNECT запроса
        first_line = request.split('\n')[0]
        target_host_port = first_line.split()[1]
        target_host, target_port = target_host_port.split(':')
        target_port = int(target_port)

        print(f"[*] Перехвачено соединение к {target_host}:{target_port}")

        # Возвращаем клиенту ответ 200, сигнализируя, что можно начать TLS-соединение
        client_socket.send(b"HTTP/1.0 200 Connection established\r\n\r\n")

        cert_file, key_file = generate_cert(target_host)

        client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        client_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        client_conn = client_context.wrap_socket(client_socket, server_side=True)

        # Создаем TCP-соединение с целевым сервером
        target_sock = socket.create_connection((target_host, target_port))
        target_conn = ssl.wrap_socket(target_sock)



        # Запуск потоков для двухстороннего проксирования
        client_to_server = threading.Thread(target=forward_data, args=(client_conn, target_conn, True))
        server_to_client = threading.Thread(target=forward_data, args=(target_conn, client_conn, False))
        client_to_server.start()
        server_to_client.start()

        # Wait for threads to finish
        client_to_server.join()
        server_to_client.join()
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        client_socket.close()
        target_sock.close()


def handle_client(client_socket):
    try:
        request = client_socket.recv(2048).decode('utf-8')

        if request.startswith("CONNECT"):
            pass
            #Обрабатываем HTTPS (CONNECT-запрос)
            handle_https(client_socket, request)
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