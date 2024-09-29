import subprocess

from fastapi import FastAPI, HTTPException
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Optional
import os
from pydantic import BaseModel

app = FastAPI()

DB_HOST = os.getenv('DB_HOST', 'postgres_db')
DB_PORT = os.getenv('DB_PORT', 5432)
DB_NAME = os.getenv('DB_NAME', 'proxy_db')
DB_USER = os.getenv('DB_USER', 'proxy_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'proxy_password')
PROXY_PORT = os.getenv('PROXY_PORT', 8080)

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except psycopg2.OperationalError as e:
        return None


class RequestRecord(BaseModel):
    id: int
    method: str
    path: str
    get_params: Optional[dict]
    headers: Optional[dict]
    cookies: Optional[dict]
    post_params: Optional[dict]
    request_time: str


class ResponseRecord(BaseModel):
    id: int
    request_id: int
    status_code: str
    status_message: str
    headers: Optional[dict]
    body: str
    response_time: str


@app.get("/requests", response_model=List[RequestRecord])
async def get_requests():
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")

    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM requests ORDER BY request_time DESC")
    requests = cursor.fetchall()

    result = [
        {
            **request,
            "request_time": request["request_time"].isoformat() if request["request_time"] else None,
            "post_params": request["post_params"] if request["post_params"] is not None else {},
            "get_params": request["get_params"] if request["get_params"] is not None else {},
            "headers": request["headers"] if request["headers"] is not None else {},
            "cookies": request["cookies"] if request["cookies"] is not None else {}
        }
        for request in requests
    ]

    cursor.close()
    conn.close()

    return result


@app.get("/requests/{id}", response_model=dict)
async def get_request_by_id(id: int):
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")

    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("SELECT * FROM requests WHERE id = %s", (id,))
    request = cursor.fetchone()

    if not request:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found.")

    cursor.execute("SELECT * FROM responses WHERE request_id = %s", (id,))
    response = cursor.fetchone()

    cursor.close()
    conn.close()

    result = {
        "request": {
            **request,
            "request_time": request["request_time"].isoformat() if request["request_time"] else None
        },
        "response": response
    }

    return result


@app.get("/repeat/{id}")
async def repeat_request(id: int):
    conn = get_db_connection()
    if conn is None:
        raise HTTPException(status_code=500, detail="Database connection failed.")

    cursor = conn.cursor(cursor_factory=RealDictCursor)

    cursor.execute("SELECT * FROM requests WHERE id = %s", (id,))
    request_data = cursor.fetchone()

    if not request_data:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found.")

    method = request_data['method']
    path = request_data['path']
    headers = request_data['headers']
    cookies = request_data['cookies']
    get_params = request_data['get_params']
    post_params = request_data['post_params']
    protocol = request_data['protocol']

    host = headers.get('Host', 'localhost')

    # Формируем конечный URL с учетом протокола
    target_url = f"{protocol.lower()}://{host}{path}"
    if get_params:
        params = '&'.join([f"{k}={v[0]}" for k, v in get_params.items()])
        target_url += f"?{params}"

    # Формируем заголовки для curl
    curl_headers = [f"-H '{key}: {value}'" for key, value in headers.items()]

    # Формируем строку с куками
    curl_cookies_str = ""
    if cookies:
        cookies_str = "; ".join([f"{key}={value}" for key, value in cookies.items()])
        curl_cookies_str = f" -b '{cookies_str}'"

    # Базовая часть curl-команды
    curl_command = f"curl -v -x http://host.docker.internal:{PROXY_PORT}/ {method} {target_url} {' '.join(curl_headers)}{curl_cookies_str}"

    if method in ["POST", "PUT", "PATCH"] and post_params:
        post_data = '&'.join([f"{k}={v[0]}" for k, v in post_params.items()])
        curl_command += f" --data '{post_data}'"

    # Если используется HTTPS, добавляем сертификат
    if protocol.lower() == "https":
        cert_path = "/api/certs/ca.crt"  # путь к сертификату
        curl_command += f" --cacert {cert_path}"

    try:

        result = subprocess.run(curl_command, shell=True, capture_output=True, text=True)

        return {
            "curl_command": curl_command,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing curl command: {e}")
    finally:
        cursor.close()
        conn.close()