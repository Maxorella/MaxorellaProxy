# MaxorellaProxy

# Как отправить запрос через прокси

curl -v -x http://127.0.0.1:8080/ http://193.108.54.41/

curl -v -x http://127.0.0.1:8080 https://mail.ru --cacert path_to/certs/ca.crt
(может достаточно долго сохраняться)

http://127.0.0.1:8000/requests/ - вывести все запросы

http://127.0.0.1:8000/requests/{id} - вывести один запрос

http://127.0.0.1:8000/repeat/{id} - повторить запрос
(тоже может выполняться какое-то время)

Если тело ответа очень большое нужно подождать (до минуты) пока ответ
сохраниться в базу данных

чтобы работал https в браузере нужно добавить корневой сертификат и сертификат каждого хоста
к которому надо подключиться и поставить для них всегда доверять.
