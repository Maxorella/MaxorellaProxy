import gzip
import json
import socket
import zlib
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

import ssl
import threading
import os
import subprocess
import psycopg2
from psycopg2 import sql


DB_HOST = os.getenv('DB_HOST', 'postgres')
DB_PORT = os.getenv('DB_PORT', 5432)
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        print("Successfully connected to the database.")
        return conn
    except psycopg2.OperationalError as e:
        print(f"Unable to connect to the database: {e}")
        return None

PROXY_PORT = 8080


def save_request_to_db(parsed_request, post_params=None, protocol="http"):
    conn = get_db_connection()
    cursor = conn.cursor()

    insert_query = sql.SQL("""
        INSERT INTO requests (method, path, get_params, headers, cookies, post_params, protocol)
        VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
    """)

    cursor.execute(insert_query, (
        parsed_request['method'],
        parsed_request['path'],
        json.dumps(parsed_request['get_params']),
        json.dumps(parsed_request['headers']),
        json.dumps(parsed_request['cookies']),
        json.dumps(post_params) if post_params else None,
        protocol
    ))

    request_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()

    return request_id

def save_response_to_db(request_id, parsed_response):
    conn = get_db_connection()
    if conn is None:
        print("Ошибка подключения к базе данных.", flush=True)
        return

    cursor = conn.cursor()

    status_code = parsed_response['code'] if parsed_response['code'] is not None else ''
    status_message = parsed_response['message'] if parsed_response['message'] is not None else ''
    headers = json.dumps(parsed_response['headers']) if parsed_response['headers'] is not None else '{}'
    body = parsed_response['body'] if parsed_response['body'] is not None else ''


    insert_query = sql.SQL("""
        INSERT INTO responses (id, request_id, status_code, status_message, headers, body)
        VALUES (%s, %s, %s, %s, %s, %s);
    """)

    try:
        cursor.execute(insert_query, (
            request_id,
            request_id,
            status_code,
            status_message,
            headers,
            body
        ))
        conn.commit()
        print("Ответ успешно сохранен в базе данных.", flush=True)
    except Exception as e:
        print(f"Ошибка при сохранении ответа в базе данных: {e}", flush=True)
    finally:
        cursor.close()
        conn.close()


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
            return str(data)
    except Exception as e:
        print(f"Ошибка: {e}")
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


    # Проверяем сжатие ответа
    if 'Content-Encoding' in headers:
        response_body = decompress_content(response_body, headers['Content-Encoding'])


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

        # Убираем "http://" из URL, если есть, и парсим хост и путь
        if url.startswith("http://"):
            url = url[len("http://"):]

        if '/' in url:
            host, path = url.split('/', 1)
            path = '/' + path  # Добавляем '/' перед путем
        else:
            host = url
            path = '/'

        port = 80  # По умолчанию порт 80
        if ':' in host:
            host, port = host.split(':')
            port = int(port)

        # Разделяем заголовки
        headers = request.split('\r\n')[1:]
        headers_dict = {}
        headers_dict = {line.split(': ')[0]: line.split(': ')[1] for line in headers if ': ' in line}

        new_request = f"{method} {path} {http_version}\r\n" + '\r\n'.join(headers) + '\r\n\r\n'
        print(new_request.replace('\r', '\\r').replace('\n', '\\n'), flush=True)
        print(f"[*] Проксируем запрос к {host}:{port}")

        # Парсим запрос
        parsed_request = parse_http_request(new_request)

        # Сохраняем запрос в базу данных
        request_id = save_request_to_db(parsed_request, None, "http")

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
        response_body_str = decompress_content(response_body, headers_dict.get('Content-Encoding', ''))

        # Парсим ответ
        parsed_response = parse_http_response(response_headers_str, response_body_str)

        headers_dict_response = parsed_response.get('headers', {})
        if isinstance(headers_dict_response, dict):
            content_encoding = headers_dict_response.get('Content-Encoding', '')
        else:
            print("dictionary format:", headers_dict_response)
            content_encoding = ''


        save_response_to_db(request_id, parsed_response)

        # Отправляем ответ клиенту
        if response:
            client_socket.sendall(response)
        else:
            print("Сервер не вернул данных.")
    except Exception as e:
        print(f"Ошибка при обработке HTTP-запроса: {e}")
    finally:
        client_socket.close()


def forward_data(src, dest, is_request, request_id):
    data = b""
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            dest.sendall(chunk)
            data += chunk
    except Exception as e:
        print(f"Error during forwarding: {e}", flush=True)
    finally:
        pass


    if is_request:
        try:
            request_str = data.decode('utf-8', errors='ignore')
            parsed_request = parse_http_request(request_str)
            save_request_to_db(parsed_request, None , "https")  # Сохраняем запрос
        except Exception as e:
            print(f"Ошибка при разборе HTTPS-запроса: {e}", flush=True)
    else:
        try:
            response_str, _, response_body = data.partition(b'\r\n\r\n')
            response_headers_str = response_str.decode('utf-8', errors='ignore')
            parsed_response = parse_http_response(response_headers_str, response_body)

            save_response_to_db(request_id, parsed_response)
        except Exception as e:
            print(f"Ошибка при разборе HTTPS-ответа: {e}", flush=True)


def get_next_request_id():
    conn = get_db_connection()
    if conn is None:
        print("Ошибка подключения к базе данных.")
        return None

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM requests;")
        next_id = cursor.fetchone()[0]
        return next_id+1
    except Exception as e:
        print(f"Ошибка при получении следующего request_id: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def handle_https(client_socket, request):
    try:
        # Получаем хост и порт из CONNECT запроса
        first_line = request.split('\n')[0]
        target_host_port = first_line.split()[1]
        target_host, target_port = target_host_port.split(':')
        target_port = int(target_port)

        print(f"[*] Перехвачено соединение к {target_host}:{target_port}")

        # Возвращаем клиенту ответ 200
        client_socket.send(b"HTTP/1.0 200 Connection established\r\n\r\n")

        # Генерация сертификата для целевого хоста
        cert_file, key_file = generate_cert(target_host)

        # Настройка SSL для клиента
        client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        client_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        client_conn = client_context.wrap_socket(client_socket, server_side=True)

        # Создаем TCP-соединение с целевым сервером
        target_sock = socket.create_connection((target_host, target_port))
        target_conn = ssl.wrap_socket(target_sock)

        # Перехватываем запросы и ответы (создаем request_id для HTTPS-запросов)
        request_id = get_next_request_id()
        print(f"request id {request_id}")

        # Запуск потоков для перенаправления данных
        client_to_server = threading.Thread(target=forward_data, args=(client_conn, target_conn, True, request_id))
        server_to_client = threading.Thread(target=forward_data, args=(target_conn, client_conn, False, request_id))
        client_to_server.start()
        server_to_client.start()

        client_to_server.join()
        server_to_client.join()
        client_conn.close()
        target_conn.close()

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
            handle_https(client_socket, request)
        else:
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
    start_proxy()