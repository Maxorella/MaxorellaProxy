openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/C=RU/ST=Moscow/L=Moscow/O=MyProxy/CN=MyProxyCA"
