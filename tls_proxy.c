#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <dirent.h>
#include <resolv.h>
#include <ifaddrs.h>
#include <net/if.h>

#define MAX_EVENTS 64
#define BUFFER_SIZE 1048576 // 1 MB
#define CERT_FILE "/data/local/tmp/quasar.yandex.ru.crt"
#define KEY_FILE "/data/local/tmp/quasar.yandex.ru.key"
#define ROOT_CA_FILE "/data/local/tmp/quasar.yandex.ru.root.crt"
#define CLIENT_CA_FILE "/data/data/com.yandex.io.sdk/files/system/ca-certificates.crt"
#define BACKEND_HOST_QUASAR "quasar.yandex.net"
#define BACKEND_HOST_KINOPOISK "graphql.kinopoisk.ru"
#define BACKEND_PORT 443
#define LISTEN_PORT_QUASAR 8443
#define LISTEN_PORT_KINOPOISK 8444
#define LISTEN_PORT_ORIGINAL BACKEND_PORT
#define MAX_CLIENTS 1000
#define CLIENT_TRAFFIC_FILE "/data/local/tmp/traffic-client.bin"
#define BACKEND_TRAFFIC_FILE "/data/local/tmp/traffic-backend.bin"
#define LOG_FILE "/data/local/tmp/proxy.log"
#define LOG_PREFIX "[DEBUG] "
#define MAX_LOG_FILE_SIZE 10485760 // 10 MB

// Макрос для отладочного вывода
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) log_error(0, LOG_PREFIX fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

// Структура для хранения пар поиска/замены
typedef struct {
    const char *search;
    const char *replace;
} ReplaceRule;

// Массив правил замены
static const ReplaceRule client_rules[] = {
    {"TvUrlAdvertisement { urls }", "TvUrlAdvertisement {      }"},
    {"TvUrlAdvertisementItem { url }", "TvUrlAdvertisementItem {     }"},
};
static const ReplaceRule backend_rules[] = {
    {"\"pinnedItems\"", "\"boringItems\""},
    {"\"customAppIconsPackages\"", "\"pinnedItems\":{},\"zzzzz\""},
    {"{\"height\":\"180\",", "{\"height\":  \"0\","},
    {"\"includeGroups\":{\"minusUsers\":true,\"notLoggedUsers\":true,\"plusUsers\":true}","\"includeGroups\":{\"minusUsers\":false,                    \"plusUsers\":false}" },
};
#define CLIENT_RULES_COUNT (sizeof(client_rules) / sizeof(client_rules[0]))
#define BACKEND_RULES_COUNT (sizeof(backend_rules) / sizeof(backend_rules[0]))

// Структура для хранения данных соединения
typedef struct {
    int client_fd;
    int backend_fd;
    SSL *client_ssl;
    SSL *backend_ssl;
    char client_buf[BUFFER_SIZE];
    char backend_buf[BUFFER_SIZE];
    size_t client_buf_len;
    size_t backend_buf_len;
    const char *backend_host;
    int listen_port;
} Connection;

// Глобальные контексты SSL и флаг завершения
SSL_CTX *client_ctx = NULL;
SSL_CTX *backend_ctx = NULL;
volatile sig_atomic_t keep_running = 1;

// Логирование ошибок и отладочных сообщений в файл и на stderr
void log_error(int include_errno, const char *fmt, ...) {
    char timestamp[32];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = snprintf(buf, sizeof(buf), "[%s] ", timestamp);
    len += vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
    if (include_errno) {
        len += snprintf(buf + len, sizeof(buf) - len, ": %s\n", strerror(errno));
    } else {
        len += snprintf(buf + len, sizeof(buf) - len, "\n");
    }
    va_end(args);

    // Проверка размера файла лога
    struct stat st;
    if (stat(LOG_FILE, &st) == 0 && st.st_size > MAX_LOG_FILE_SIZE) {
        if (unlink(LOG_FILE) == 0) {
            DEBUG_PRINT("Log file %s exceeded %ld bytes, removed", LOG_FILE, MAX_LOG_FILE_SIZE);
        } else {
            fprintf(stderr, "[%s] Failed to remove log file %s: %s\n", timestamp, LOG_FILE, strerror(errno));
        }
    }

    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
    write(STDERR_FILENO, buf, len);
}

// Функция для замены строк в буфере (in-place)
void replace_strings(char *buf, size_t *len, const ReplaceRule *rules, size_t rules_count, const char *direction) {
    for (size_t i = 0; i < *len; ) {
        int matched = 0;
        for (size_t r = 0; r < rules_count; r++) {
            size_t search_len = strlen(rules[r].search);
            if (i + search_len <= *len && memcmp(buf + i, rules[r].search, search_len) == 0) {
                memcpy(buf + i, rules[r].replace, search_len);
                i += search_len;
                DEBUG_PRINT("Replaced '%s' with '%s' in %s traffic", rules[r].search, rules[r].replace, direction);
                matched = 1;
                break;
            }
        }
        if (!matched) {
            i++;
        }
    }
}

// Чтение содержимого файла в строку
char *read_file_content(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        log_error(1, "Failed to open file %s", filename);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    if (size < 0) {
        log_error(1, "Failed to get size of file %s", filename);
        fclose(fp);
        return NULL;
    }
    fseek(fp, 0, SEEK_SET);

    char *content = malloc(size + 1);
    if (!content) {
        log_error(1, "malloc for file content %s", filename);
        fclose(fp);
        return NULL;
    }

    size_t read_size = fread(content, 1, size, fp);
    if (read_size != (size_t)size) {
        log_error(1, "Failed to read file %s", filename);
        free(content);
        fclose(fp);
        return NULL;
    }
    content[size] = '\0';
    fclose(fp);

    DEBUG_PRINT("Read %ld bytes from %s", size, filename);
    return content;
}

// Проверка, содержит ли файл указанную строку
int file_contains_content(const char *filename, const char *content) {
    char *file_content = read_file_content(filename);
    if (!file_content) {
        return -1;
    }

    int contains = (strstr(file_content, content) != NULL);
    free(file_content);
    return contains;
}

// Добавление корневого CA в файл доверенных сертификатов клиента
int append_root_ca_to_client() {
    char *root_ca_content = read_file_content(ROOT_CA_FILE);
    if (!root_ca_content) {
        return -1;
    }

    int contains = file_contains_content(CLIENT_CA_FILE, root_ca_content);
    if (contains < 0) {
        free(root_ca_content);
        log_error(1, "Failed to check if %s contains root CA", CLIENT_CA_FILE);
        return -1;
    }
    if (contains) {
        DEBUG_PRINT("Root CA already present in %s, skipping append", CLIENT_CA_FILE);
        free(root_ca_content);
        return 0;
    }

    int fd = open(CLIENT_CA_FILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) {
        log_error(1, "Failed to open %s for appending", CLIENT_CA_FILE);
        free(root_ca_content);
        return -1;
    }

    size_t len = strlen(root_ca_content);
    if (write(fd, root_ca_content, len) != (ssize_t)len) {
        log_error(1, "Failed to write to %s", CLIENT_CA_FILE);
        close(fd);
        free(root_ca_content);
        return -1;
    }

    close(fd);
    free(root_ca_content);
    DEBUG_PRINT("Appended root CA to %s", CLIENT_CA_FILE);
    return 0;
}

// Обработка ошибки SSL alert number 48 (unknown ca)
void handle_unknown_ca_error() {
    DEBUG_PRINT("Detected SSL alert number 48 (unknown ca), attempting to append root CA");
    if (append_root_ca_to_client() == 0) {
        DEBUG_PRINT("Successfully handled unknown ca error");
    } else {
        log_error(1, "Failed to handle unknown ca error");
    }
}

// Получение локальных IP-адресов устройства
int get_local_ips(struct in_addr **local_ips, size_t *count) {
    struct ifaddrs *ifaddr, *ifa;
    size_t ip_count = 0;
    struct in_addr *ips = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        log_error(1, "getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        ip_count++;
    }

    if (ip_count == 0) {
        freeifaddrs(ifaddr);
        *local_ips = NULL;
        *count = 0;
        return 0;
    }

    ips = malloc(ip_count * sizeof(struct in_addr));
    if (!ips) {
        log_error(1, "malloc local_ips");
        freeifaddrs(ifaddr);
        return -1;
    }

    size_t i = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        ips[i] = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ips[i], ip_str, INET_ADDRSTRLEN);
        DEBUG_PRINT("Found local IP: %s", ip_str);
        i++;
    }

    freeifaddrs(ifaddr);
    *local_ips = ips;
    *count = ip_count;
    return 0;
}

// Функция для получения PID клиентского процесса
pid_t get_client_pid(struct sockaddr_in *client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, INET_ADDRSTRLEN);
    DEBUG_PRINT("Checking client IP: %s", client_ip);

    struct in_addr *local_ips = NULL;
    size_t local_ip_count = 0;
    if (get_local_ips(&local_ips, &local_ip_count) < 0) {
        log_error(1, "get_local_ips");
        return -1;
    }

    int is_local = 0;
    if (client_addr->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        is_local = 1;
        DEBUG_PRINT("Client IP is loopback (127.0.0.1)");
    } else {
        for (size_t i = 0; i < local_ip_count; i++) {
            if (client_addr->sin_addr.s_addr == local_ips[i].s_addr) {
                is_local = 1;
                DEBUG_PRINT("Client IP matches device IP");
                break;
            }
        }
    }

    free(local_ips);
    if (!is_local) {
        DEBUG_PRINT("Client IP is not local");
        return -1;
    }

    char line[1024];
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp) {
        log_error(1, "Failed to open /proc/net/tcp");
        return -1;
    }

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }

    uint16_t client_port = ntohs(client_addr->sin_port);
    uint32_t client_addr_int = client_addr->sin_addr.s_addr;
    unsigned long inode = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned int laddr, lport, raddr, rport;
        char state[16];
        unsigned long long inodenum = 0;
        int scanned = sscanf(line, "%*d: %x:%x %x:%x %s %*x:%*x %*x:%*x %*x %*d %*d %llu",
                             &laddr, &lport, &raddr, &rport, state, &inodenum);
        if (scanned < 6) continue;

        if (strcmp(state, "01") == 0 && laddr == client_addr_int && lport == client_port &&
            rport == LISTEN_PORT_ORIGINAL) {
            inode = inodenum;
            break;
        }
    }
    fclose(fp);

    if (inode == 0) {
//        log_error(1, "No matching socket found in /proc/net/tcp");
        return -1;
    }

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        log_error(1, "Failed to open /proc");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir))) {
        if (entry->d_type != DT_DIR) continue;
        char *endptr;
        pid_t pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        char fd_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir))) {
            if (fd_entry->d_type != DT_LNK) continue;
            char link_path[512], target[256];
            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path, target, sizeof(target) - 1);
            if (len < 0) continue;
            target[len] = '\0';

            if (strncmp(target, "socket:[", 8) == 0) {
                unsigned long socket_inode = strtoul(target + 8, NULL, 10);
                if (socket_inode == inode) {
                    closedir(fd_dir);
                    closedir(proc_dir);
                    return pid;
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);

    log_error(1, "No process found with matching socket inode %lu", inode);
    return -1;
}

// Функции для записи трафика
void log_client_traffic(const char *data, size_t len, const char *backend_host) {
    // Проверка размера файла трафика
    struct stat st;
    if (stat(CLIENT_TRAFFIC_FILE, &st) == 0 && st.st_size > MAX_LOG_FILE_SIZE) {
        if (unlink(CLIENT_TRAFFIC_FILE) == 0) {
            DEBUG_PRINT("Client traffic file %s exceeded %ld bytes, removed", CLIENT_TRAFFIC_FILE, MAX_LOG_FILE_SIZE);
        } else {
            char timestamp[32];
            time_t now = time(NULL);
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
            fprintf(stderr, "[%s] Failed to remove client traffic file %s: %s\n", timestamp, CLIENT_TRAFFIC_FILE, strerror(errno));
        }
    }

    int fd = open(CLIENT_TRAFFIC_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        log_error(1, "open client traffic file");
        return;
    }
    if (write(fd, data, len) < 0) {
        log_error(1, "write client traffic");
    }
    close(fd);
//    DEBUG_PRINT("Logged %zu bytes of client traffic for backend %s", len, backend_host);
}

void log_backend_traffic(const char *data, size_t len, const char *backend_host) {
    // Проверка размера файла трафика
    struct stat st;
    if (stat(BACKEND_TRAFFIC_FILE, &st) == 0 && st.st_size > MAX_LOG_FILE_SIZE) {
        if (unlink(BACKEND_TRAFFIC_FILE) == 0) {
            DEBUG_PRINT("Backend traffic file %s exceeded %ld bytes, removed", BACKEND_TRAFFIC_FILE, MAX_LOG_FILE_SIZE);
        } else {
            char timestamp[32];
            time_t now = time(NULL);
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
            fprintf(stderr, "[%s] Failed to remove backend traffic file %s: %s\n", timestamp, BACKEND_TRAFFIC_FILE, strerror(errno));
        }
    }

    int fd = open(BACKEND_TRAFFIC_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        log_error(1, "open backend traffic file");
        return;
    }
    if (write(fd, data, len) < 0) {
        log_error(1, "write backend traffic");
    }
    close(fd);
//    DEBUG_PRINT("Logged %zu bytes of backend traffic for backend %s", len, backend_host);
}

// Обработчик сигналов
void signal_handler(int sig) {
    log_error(1, "Received signal %d", sig);
    keep_running = 0;
}

// Инициализация OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Инициализация резолвера с пользовательскими DNS-серверами
void init_resolver() {
    res_init();

    struct in_addr addr;
    _res.nscount = 2;

    if (inet_aton("77.88.8.8", &addr) == 0) {
        log_error(1, "Invalid DNS server address: 77.88.8.8");
        exit(EXIT_FAILURE);
    }
    _res.nsaddr_list[0].sin_addr = addr;
    _res.nsaddr_list[0].sin_family = AF_INET;
    _res.nsaddr_list[0].sin_port = htons(53);

    if (inet_aton("8.8.8.8", &addr) == 0) {
        log_error(1, "Invalid DNS server address: 8.8.8.8");
        exit(EXIT_FAILURE);
    }
    _res.nsaddr_list[1].sin_addr = addr;
    _res.nsaddr_list[1].sin_family = AF_INET;
    _res.nsaddr_list[1].sin_port = htons(53);

    DEBUG_PRINT("Resolver initialized with DNS servers 77.88.8.8 and 8.8.8.8");
}

// Создание контекста для клиентских соединений
SSL_CTX *create_client_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error(1, "SSL_CTX_new client");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); // Отключаем только SSLv2, разрешаем SSLv3 и выше

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        log_error(1, "SSL_CTX_use_certificate/key_file");
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        log_error(1, "Private key does not match certificate");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Создание контекста для бэкенд-соединений
SSL_CTX *create_backend_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error(1, "SSL_CTX_new backend");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); // Отключаем только SSLv2, разрешаем SSLv3 и выше
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

// Создание серверного сокета
int create_server_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error(1, "socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error(1, "setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error(1, "bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, SOMAXCONN) < 0) {
        log_error(1, "listen");
        exit(EXIT_FAILURE);
    }

    DEBUG_PRINT("Server socket created on port %d", port);
    return sock;
}

// Подключение к бэкенду
int connect_to_backend(const char *backend_host) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Поддержка IPv4 и IPv6
    hints.ai_socktype = SOCK_STREAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", BACKEND_PORT);
    int gai_ret = getaddrinfo(backend_host, port_str, &hints, &res);
    if (gai_ret != 0) {
        log_error(1, "getaddrinfo failed for %s: %s", backend_host, gai_strerror(gai_ret));
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        log_error(1, "socket backend");
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        log_error(1, "connect backend %s", backend_host);
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    DEBUG_PRINT("Connected to backend %s:%d", backend_host, BACKEND_PORT);
    return sock;
}

// Обработка соединения
void *handle_connection(void *arg) {
    Connection *conn = (Connection *)arg;
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_error(1, "epoll_create1");
        goto cleanup;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = conn->client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->client_fd, &ev) < 0) {
        log_error(1, "epoll_ctl client");
        goto cleanup;
    }
    ev.data.fd = conn->backend_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->backend_fd, &ev) < 0) {
        log_error(1, "epoll_ctl backend");
        goto cleanup;
    }

    while (keep_running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_error(1, "epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            char *buf = (fd == conn->client_fd) ? conn->client_buf : conn->backend_buf;
            size_t *buf_len = (fd == conn->client_fd) ? &conn->client_buf_len : &conn->backend_buf_len;
            SSL *src_ssl = (fd == conn->client_fd) ? conn->client_ssl : conn->backend_ssl;
            SSL *dst_ssl = (fd == conn->client_fd) ? conn->backend_ssl : conn->client_ssl;
            const ReplaceRule *rules = (fd == conn->client_fd) ? client_rules : backend_rules;
            size_t rules_count = (fd == conn->client_fd) ? CLIENT_RULES_COUNT : BACKEND_RULES_COUNT;
            const char *direction = (fd == conn->client_fd) ? "client" : "backend";

            int bytes = SSL_read(src_ssl, buf + *buf_len, BUFFER_SIZE - *buf_len);
            if (bytes <= 0) {
                int ssl_err = SSL_get_error(src_ssl, bytes);
                if (ssl_err == SSL_ERROR_ZERO_RETURN || ssl_err == SSL_ERROR_SYSCALL) {
                    goto cleanup;
                }
                continue;
            }

            *buf_len += bytes;
            replace_strings(buf, buf_len, rules, rules_count, direction);

            if (fd == conn->client_fd) {
                log_client_traffic(buf, *buf_len, conn->backend_host);
            } else {
                log_backend_traffic(buf, *buf_len, conn->backend_host);
            }

            while (*buf_len > 0) {
                int written = SSL_write(dst_ssl, buf, *buf_len);
                if (written <= 0) {
                    int ssl_err = SSL_get_error(dst_ssl, written);
                    if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                        continue;
                    }
                    goto cleanup;
                }
                memmove(buf, buf + written, *buf_len - written);
                *buf_len -= written;
            }
        }
    }

cleanup:
    if (conn->client_ssl) {
        SSL_shutdown(conn->client_ssl);
        SSL_free(conn->client_ssl);
    }
    if (conn->backend_ssl) {
        SSL_shutdown(conn->backend_ssl);
        SSL_free(conn->backend_ssl);
    }
    if (conn->client_fd >= 0) close(conn->client_fd);
    if (conn->backend_fd >= 0) close(conn->backend_fd);
    if (epoll_fd >= 0) close(epoll_fd);
    free(conn);
    return NULL;
}

// Главная функция прокси
void *run_proxy(void *arg) {
    struct proxy_args {
        int port;
        const char *backend_host;
    } *args = (struct proxy_args *)arg;
    int port = args->port;
    const char *backend_host = args->backend_host;

    // Инициализация resolver'а для текущего потока
    init_resolver();

    int server_fd = create_server_socket(port);
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_error(1, "epoll_create1 server for port %d", port);
        close(server_fd);
        return NULL;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        log_error(1, "epoll_ctl server for port %d", port);
        close(epoll_fd);
        close(server_fd);
        return NULL;
    }

    while (keep_running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_error(1, "epoll_wait server for port %d", port);
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                if (client_fd < 0) {
                    log_error(1, "accept on port %d", port);
                    continue;
                }

                Connection *conn = calloc(1, sizeof(Connection));
                if (!conn) {
                    log_error(1, "calloc connection on port %d", port);
                    close(client_fd);
                    continue;
                }

                conn->client_fd = client_fd;
                conn->backend_host = backend_host;
                conn->listen_port = port;
                conn->client_ssl = SSL_new(client_ctx);
                if (!conn->client_ssl) {
                    log_error(1, "SSL_new client on port %d", port);
                    close(client_fd);
                    free(conn);
                    continue;
                }

                SSL_set_fd(conn->client_ssl, conn->client_fd);
                int ssl_accept_ret = SSL_accept(conn->client_ssl);
                if (ssl_accept_ret <= 0) {
                    unsigned long err = ERR_get_error();
                    char err_buf[256];
                    ERR_error_string_n(err, err_buf, sizeof(err_buf));
                    int retry = 0;
                    if (strstr(err_buf, "tlsv1 alert unknown ca") || strstr(err_buf, "sslv3 alert certificate unknown")) {
                        handle_unknown_ca_error();
                        DEBUG_PRINT("Retrying SSL_accept after handling unknown ca or certificate unknown on port %d", port);
                        ssl_accept_ret = SSL_accept(conn->client_ssl);
                        if (ssl_accept_ret > 0) {
                            retry = 1;
                        } else {
                            err = ERR_get_error();
                            ERR_error_string_n(err, err_buf, sizeof(err_buf));
                        }
                    }
                    if (!retry) {
                        int ssl_err = SSL_get_error(conn->client_ssl, ssl_accept_ret);
                        DEBUG_PRINT("SSL_accept failed on port %d: %s, SSL error code: %d", port, err_buf, ssl_err);
                        log_error(1, "SSL_accept on port %d: %s", port, err_buf);
                        SSL_free(conn->client_ssl);
                        close(client_fd);
                        free(conn);
                        continue;
                    }
                }

                const char *sni_name = SSL_get_servername(conn->client_ssl, TLSEXT_NAMETYPE_host_name);
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                uint16_t client_port = ntohs(client_addr.sin_port);

                pid_t client_pid = get_client_pid(&client_addr);
                if (client_pid != -1) {
                    if (sni_name && *sni_name) {
                        DEBUG_PRINT("Client connected from %s:%u to port %d, PID: %d, SNI: %s, backend: %s",
                                    client_ip, client_port, port, client_pid, sni_name, backend_host);
                    } else {
                        DEBUG_PRINT("Client connected from %s:%u to port %d, PID: %d, no SNI provided,",
                                    client_ip, client_port, port, client_pid);
                    }
                } else {
                    if (sni_name && *sni_name) {
                        DEBUG_PRINT("Client connected from %s:%u to port %d, SNI: %s, backend: %s",
                                    client_ip, client_port, port, sni_name, backend_host);
                    } else {
                        DEBUG_PRINT("Client connected from %s:%u to port %d, no SNI provided, backend: %s",
                                    client_ip, client_port, port, backend_host);
                    }
                }

                conn->backend_fd = connect_to_backend(backend_host);
                if (conn->backend_fd < 0) {
                    SSL_free(conn->client_ssl);
                    close(client_fd);
                    free(conn);
                    continue;
                }

                conn->backend_ssl = SSL_new(backend_ctx);
                if (!conn->backend_ssl) {
                    log_error(1, "SSL_new backend");
                    close(conn->backend_fd);
                    SSL_free(conn->client_ssl);
                    close(client_fd);
                    free(conn);
                    continue;
                }

                SSL_set_fd(conn->backend_ssl, conn->backend_fd);
                if (sni_name && *sni_name) {
                    if (!SSL_set_tlsext_host_name(conn->backend_ssl, sni_name)) {
                        log_error(1, "SSL_set_tlsext_host_name on port %d", port);
                        SSL_free(conn->backend_ssl);
                        close(conn->backend_fd);
                        SSL_free(conn->client_ssl);
                        close(client_fd);
                        free(conn);
                        continue;
                    }
                }

                if (SSL_connect(conn->backend_ssl) <= 0) {
                    char err_buf[256];
                    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                    log_error(1, "SSL_connect on port %d: %s", port, err_buf);
                    SSL_free(conn->backend_ssl);
                    close(conn->backend_fd);
                    SSL_free(conn->client_ssl);
                    close(client_fd);
                    free(conn);
                    continue;
                }

                pthread_t thread;
                if (pthread_create(&thread, NULL, handle_connection, conn) != 0) {
                    log_error(1, "pthread_create on port %d", port);
                    SSL_free(conn->backend_ssl);
                    close(conn->backend_fd);
                    SSL_free(conn->client_ssl);
                    close(client_fd);
                    free(conn);
                    continue;
                }
                pthread_detach(thread);
            }
        }
    }

    close(epoll_fd);
    close(server_fd);
    DEBUG_PRINT("Proxy on port %d terminated", port);
    return NULL;
}

int main() {
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    init_openssl();
    client_ctx = create_client_context();
    backend_ctx = create_backend_context();

    struct proxy_args {
        int port;
        const char *backend_host;
    } args_quasar = {LISTEN_PORT_QUASAR, BACKEND_HOST_QUASAR},
      args_kinopoisk = {LISTEN_PORT_KINOPOISK, BACKEND_HOST_KINOPOISK};

    pthread_t quasar_thread, kinopoisk_thread;
    if (pthread_create(&quasar_thread, NULL, run_proxy, &args_quasar) != 0) {
        log_error(1, "pthread_create for quasar proxy");
        goto cleanup_exit;
    }
    if (pthread_create(&kinopoisk_thread, NULL, run_proxy, &args_kinopoisk) != 0) {
        log_error(1, "pthread_create for kinopoisk proxy");
        keep_running = 0;
        pthread_join(quasar_thread, NULL);
        goto cleanup_exit;
    }

    pthread_join(quasar_thread, NULL);
    pthread_join(kinopoisk_thread, NULL);

cleanup_exit:
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(backend_ctx);
    EVP_cleanup();
    log_error(1, "Proxy terminated");
    return 0;
}