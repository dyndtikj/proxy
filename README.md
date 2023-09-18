## Задание

- /requests – список запросов
- /requests/id – вывод 1 запроса
- /repeat/id – повторная отправка запроса
- /scan/id – сканирование запроса на XXE

Дополнительные

- /responses – вывод всех ответов
- /response?req_id=blablablabla – получение ответа на запрос по req_id

Установка:



install cert to root:

mac:

`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "cert_data/cert.pem"`

linux:

`apt-get install -y ca-certificates`

`cp /app/cert_data/cert.pem /usr/local/share/ca-certificates/cert.crt`

`chmod 644 /usr/local/share/ca-certificates/cert.crt`

`update-ca-certificates`

run with prebuild proxy:

`make run`

run with build:

`docker-compose up --build mongo` 

`make build`

`make run_bin`

Для более продвинутого поиска и визуализации можно использовать MongoDB Compass 

Очистить базу:

`rm -rf ./data`

Включить проксирование в системе:

mac:

settings -> proxy -> web proxy (HTTP) + secure web proxy (HTTPS) -> set addr to 127.0.0.1 port 8080