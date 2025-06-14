# Отключение рекламы на устрйоствах Яндекс

Статья: 

Сборка:
arm-linux-gnueabihf-gcc -static -DDEBUG -o tls_proxy tls_proxy.c -lssl -lcrypto -pthread 
(требуется openssl-dev)