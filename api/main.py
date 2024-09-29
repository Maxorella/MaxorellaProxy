from fastapi import FastAPI, HTTPException
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Optional
import os
from pydantic import BaseModel
from datetime import datetime

app = FastAPI()

DB_HOST = os.getenv('DB_HOST', 'postgres_db')
DB_PORT = os.getenv('DB_PORT', 5432)
DB_NAME = os.getenv('DB_NAME', 'proxy_db')
DB_USER = os.getenv('DB_USER', 'proxy_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'proxy_password')


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
    get_params: Optional[dict]  # Сделать опциональным
    headers: Optional[dict]      # Сделать опциональным
    cookies: Optional[dict]      # Сделать опциональным
    post_params: Optional[dict]  # Сделать опциональным
    request_time: str


class ResponseRecord(BaseModel):
    id: int
    request_id: int
    status_code: str
    status_message: str
    headers: Optional[dict]  # Сделать опциональным
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

    # Преобразование данных перед возвратом
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

    # Fetch the request
    cursor.execute("SELECT * FROM requests WHERE id = %s", (id,))
    request = cursor.fetchone()

    if not request:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found.")

    # Fetch the corresponding response
    cursor.execute("SELECT * FROM responses WHERE request_id = %s", (id,))
    response = cursor.fetchone()

    cursor.close()
    conn.close()

    # Combine request and response
    result = {
        "request": {
            **request,
            "request_time": request["request_time"].isoformat() if request["request_time"] else None
        },
        "response": response
    }

    return result


@app.get("/health")
async def health_check():
    return {"status": "OK"}
