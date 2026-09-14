# -c-
输入ip地址 起始端口 结尾端口
// myscan.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h> // 解决 clock_t 报错

#ifdef _WIN32
    #define _WIN32_WINNT 0x0600 // 解决 inet_pton 警告
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef int socklen_t;
    #define CLOSE_SOCKET closesocket
    #define GET_LAST_ERROR WSAGetLastError()
    #define WOULD_BLOCK WSAEWOULDBLOCK
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <sys/time.h>
    #include <netdb.h>
    #define CLOSE_SOCKET close
    #define GET_LAST_ERROR errno
    #define WOULD_BLOCK EINPROGRESS
#endif

#define MAX_THREADS 256
#define DEFAULT_TIMEOUT_MS 800

typedef struct {
    char       ip[64];
    int        start_port;
    int        end_port;
    int        thread_count;
    int        timeout_ms;
    pthread_mutex_t port_mutex;
    int        next_port;
    pthread_mutex_t print_mutex;
} ScannerCtx;

static ScannerCtx g_ctx;

const char* guess_service(int port) {
    switch (port) {
        case 21: return "ftp";   case 22: return "ssh";
        case 23: return "telnet";case 25: return "smtp";
        case 53: return "domain";case 80: return "http";
        case 110: return "pop3"; case 443: return "https";
        case 445: return "microsoft-ds"; case 3306: return "mysql";
        case 3389: return "ms-wbt-server"; case 5432: return "postgresql";
        case 6379: return "redis"; case 8080: return "http-proxy";
        default: return "unknown";
    }
}

int try_connect(const char *ip, int port, int timeout_ms) {
#ifdef _WIN32
    SOCKET sockfd;
#else
    int sockfd;
#endif
    struct sockaddr_in addr;
    struct timeval tv;
    fd_set wfds;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (sockfd == INVALID_SOCKET) return -1;
    unsigned long mode = 1;
    ioctlsocket(sockfd, FIONBIO, &mode);
#else
    if (sockfd < 0) return -1;
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        CLOSE_SOCKET(sockfd);
        return -1;
    }

    int ret = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        if (GET_LAST_ERROR != WOULD_BLOCK) {
            CLOSE_SOCKET(sockfd);
            return 0;
        }
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
        ret = select(0, NULL, &wfds, NULL, &tv);
#else
        ret = select(sockfd + 1, NULL, &wfds, NULL, &tv);
#endif
        if (ret <= 0) { CLOSE_SOCKET(sockfd); return 0; }
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) {
            CLOSE_SOCKET(sockfd);
            return 0;
        }
    }
    CLOSE_SOCKET(sockfd);
    return 1;
}

void* worker(void *arg) {
    (void)arg;
    while (1) {
        pthread_mutex_lock(&g_ctx.port_mutex);
        if (g_ctx.next_port > g_ctx.end_port) {
            pthread_mutex_unlock(&g_ctx.port_mutex);
            break;
        }
        int port = g_ctx.next_port++;
        pthread_mutex_unlock(&g_ctx.port_mutex);

        if (try_connect(g_ctx.ip, port, g_ctx.timeout_ms) == 1) {
            pthread_mutex_lock(&g_ctx.print_mutex);
            printf("[+] %s:%d\topen\t%s\n", g_ctx.ip, port, guess_service(port));
            fflush(stdout);
            pthread_mutex_unlock(&g_ctx.print_mutex);
        }
    }
    return NULL;
}

int resolve_host(const char *host, char *out_ip, size_t out_size) {
    struct in_addr a;
    if (inet_pton(AF_INET, host, &a) == 1) {
        strncpy(out_ip, host, out_size - 1);
        return 0;
    }
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
    struct sockaddr_in *sa = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, out_ip, out_size);
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;
#endif
    if (argc < 4) {
        printf("用法: %s <目标IP/域名> <起始端口> <结束端口> [线程数=100] [超时ms=800]\n", argv[0]);
        return 1;
    }
    memset(&g_ctx, 0, sizeof(g_ctx));
    if (resolve_host(argv[1], g_ctx.ip, sizeof(g_ctx.ip)) != 0) {
        fprintf(stderr, "无法解析主机: %s\n", argv[1]);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    g_ctx.start_port = atoi(argv[2]);
    g_ctx.end_port   = atoi(argv[3]);
    g_ctx.thread_count = (argc >= 5) ? atoi(argv[4]) : 100;
    g_ctx.timeout_ms   = (argc >= 6) ? atoi(argv[5]) : DEFAULT_TIMEOUT_MS;
    if (g_ctx.thread_count > MAX_THREADS) g_ctx.thread_count = MAX_THREADS;

    printf("开始扫描 %s (%s) 端口 %d-%d, 线程=%d\n", argv[1], g_ctx.ip, g_ctx.start_port, g_ctx.end_port, g_ctx.thread_count);
    printf("--------------------------------------------------\n");

    g_ctx.next_port = g_ctx.start_port;
    pthread_mutex_init(&g_ctx.port_mutex, NULL);
    pthread_mutex_init(&g_ctx.print_mutex, NULL);

#ifdef _WIN32
    DWORD start_time = GetTickCount(); // Windows 专属计时
#else
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
#endif

    pthread_t threads[MAX_THREADS];
    for (int i = 0; i < g_ctx.thread_count; i++) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            g_ctx.thread_count = i; break;
        }
    }
    for (int i = 0; i < g_ctx.thread_count; i++) pthread_join(threads[i], NULL);

#ifdef _WIN32
    double elapsed = (GetTickCount() - start_time) / 1000.0; // 正确计时
#else
    gettimeofday(&t1, NULL);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1000000.0;
#endif
    printf("--------------------------------------------------\n");
    printf("扫描完成, 耗时 %.2f 秒\n", elapsed);

    pthread_mutex_destroy(&g_ctx.port_mutex);
    pthread_mutex_destroy(&g_ctx.print_mutex);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
