# Отключение рекламы на устройствах Яндекс

Статья: https://dzen.ru/a/aE2nH724O0UJBTL_


Сборка:
arm-linux-gnueabihf-gcc -static -DDEBUG -o tls_proxy tls_proxy.c -lssl -lcrypto -pthread   
(требуется openssl-dev для armhf, либо собранный из исходников openssl версии 3.0.1 или выше).
