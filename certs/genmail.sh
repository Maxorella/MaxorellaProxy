openssl genrsa -out mail.ru.key 2048
openssl req -new -key mail.ru.key -out mail.ru.csr -subj "/C=RU/ST=Moscow/L=Moscow/O=MyProxy/CN=mail.ru"
openssl x509 -req -in mail.ru.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out mail.ru.crt -days 365 -sha256
