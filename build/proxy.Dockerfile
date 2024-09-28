FROM python:3.9-slim

WORKDIR /proxy

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY /proxy/ .

RUN mkdir -p certs

EXPOSE 8080

CMD ["python", "main.py"]

