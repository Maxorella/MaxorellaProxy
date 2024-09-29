# Dockerfile для FastAPI API
FROM python:3.9-slim

# Устанавливаем зависимости
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY ./api/main.py /app
EXPOSE 8000
# Команда для запуска API с использованием uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
