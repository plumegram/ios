// StandCore net-redirect + logger
// Хукает connect(): пишет в лог реальный адрес назначения и переписывает IP на наш сервер.
#include <jni.h>
#include <android/log.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <ctime>

#include "Dobby/dobby.h"

#define TAG "StandCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// куда заворачиваем
static const char *SC_SERVER_IP = "2.26.123.219";
// адреса, которые НЕ трогаем (google/firebase/telemetry и локалка)
static bool is_private_or_google(uint32_t be_addr) {
    uint32_t a = ntohl(be_addr);
    uint8_t o1 = (a >> 24) & 0xFF, o2 = (a >> 16) & 0xFF;
    if (o1 == 10 || o1 == 127 || o1 == 0) return true;              // локальные
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return true;
    if (o1 == 192 && o2 == 168) return true;
    if (o1 == 100 && o2 >= 64 && o2 <= 127) return true;            // CGNAT оператора
    if (o1 == 142 || o1 == 172 || o1 == 216 || o1 == 74 || o1 == 173) return true; // google-ish
    if (o1 == 34 || o1 == 35) return true;                          // gcp
    return false;
}

static char g_logpath[256] = "/sdcard/net.log";
static char g_pkg[128] = {0};

// имя пакета берём из /proc/self/cmdline, чтобы либа не зависела от переименований
static void sc_init_paths() {
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) {
        if (fgets(g_pkg, sizeof(g_pkg), f)) {
            char *colon = strchr(g_pkg, ':');   // отбросить суффикс процесса
            if (colon) *colon = 0;
        }
        fclose(f);
    }
    if (g_pkg[0]) {
        char dir[200];
        snprintf(dir, sizeof(dir), "/sdcard/Android/data/%s", g_pkg);
        mkdir(dir, 0777);
        snprintf(dir, sizeof(dir), "/sdcard/Android/data/%s/files", g_pkg);
        mkdir(dir, 0777);
        snprintf(g_logpath, sizeof(g_logpath), "/sdcard/Android/data/%s/files/net.log", g_pkg);
    }
}

static void sc_log(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOGI("%s", buf);
    FILE *f = fopen(g_logpath, "a");
    if (f) {
        time_t t = time(nullptr);
        struct tm tmv; localtime_r(&t, &tmv);
        fprintf(f, "[%02d:%02d:%02d] %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, buf);
        fclose(f);
    }
}

static void install_tls_bypass();
static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = nullptr;

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *) addr;
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        int port = ntohs(in->sin_port);

        // HTTP/HTTPS не трогаем: это обновления, конфиги, аналитика — им нужен настоящий интернет
        if (port == 80 || port == 443 || port == 8080) {
            sc_log("connect %s:%d  (web, пропущен)", ip, port);
            return orig_connect(sockfd, addr, addrlen);
        }
        if (!is_private_or_google(in->sin_addr.s_addr)) {
            struct sockaddr_in patched;
            memcpy(&patched, in, sizeof(patched));
            inet_pton(AF_INET, SC_SERVER_IP, &patched.sin_addr);
            sc_log("connect %s:%d  ->  %s:%d (redirect)", ip, port, SC_SERVER_IP, port);
            return orig_connect(sockfd, (struct sockaddr *) &patched, addrlen);
        }
        sc_log("connect %s:%d  (пропущен)", ip, port);
    } else if (addr && addr->sa_family == AF_INET6) {
        sc_log("connect ipv6 (пропущен)");
    }
    return orig_connect(sockfd, addr, addrlen);
}

static void *worker(void *) {
    sc_init_paths();
    sc_log("=== StandCore lib загружена, пакет %s, сервер %s ===", g_pkg, SC_SERVER_IP);

    void *sym = dlsym(RTLD_DEFAULT, "connect");
    if (!sym) { sc_log("connect не найден"); return nullptr; }
    if (DobbyHook(sym, (void *) hook_connect, (void **) &orig_connect) == 0)
        sc_log("хук connect установлен @ %p", sym);
    else
        sc_log("не удалось поставить хук connect");
    install_tls_bypass();
    return nullptr;
}

// ---- обход TLS pinning (UnityTLS) ----
#include <cstdint>
static uintptr_t get_module_base(const char *name) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            base = (uintptr_t) strtoull(line, nullptr, 16);
            break;
        }
    }
    fclose(f);
    return base;
}

// unitytls_x509verify_result: 0 == UNITYTLS_X509VERIFY_SUCCESS
typedef uint32_t (*verify3_t)(void *, void *, void *);
typedef uint32_t (*verify4_t)(void *, void *, uint32_t, void *);
static verify3_t o_VerifyCallback = nullptr;
static verify4_t o_x509verify = nullptr;

static uint32_t h_VerifyCallback(void *u, void *chain, void *err) {
    if (o_VerifyCallback) o_VerifyCallback(u, chain, err); // дать отработать, но результат перебить
    return 0;
}
static uint32_t h_x509verify(void *u, void *cert, uint32_t res, void *err) {
    return 0;
}

static void install_tls_bypass() {
    uintptr_t base = 0;
    for (int i = 0; i < 60 && !base; i++) { base = get_module_base("libil2cpp.so"); if (!base) usleep(500000); }
    if (!base) { sc_log("libil2cpp.so не найден — pinning не обойдён"); return; }
    sc_log("libil2cpp base=%p", (void*)base);
    // RVA специфичны для версии И архитектуры (взяты из Il2CppDumper по каждому .so 0.25).
#if defined(__aarch64__)
    uintptr_t rva_vc = 0x26173C0;   // UnityTlsContext.VerifyCallback (arm64-v8a)
    uintptr_t rva_xv = 0x261A248;   // UnityTlsContext.x509verify_callback (arm64-v8a)
#elif defined(__arm__)
    // Thumb: Dobby принимает выровненный адрес; младший бит режем на всякий случай.
    uintptr_t rva_vc = 0x24BF00C & ~1u;   // VerifyCallback (armeabi-v7a)
    uintptr_t rva_xv = 0x24C2C40 & ~1u;   // x509verify_callback (armeabi-v7a)
#else
    uintptr_t rva_vc = 0, rva_xv = 0;
#endif
    if (!rva_vc) { sc_log("арх не поддержана для TLS-байпаса"); return; }
    void *vc = (void *)(base + rva_vc);
    void *xv = (void *)(base + rva_xv);
    if (DobbyHook(vc, (void*)h_VerifyCallback, (void**)&o_VerifyCallback)==0) sc_log("hook VerifyCallback ok");
    else sc_log("hook VerifyCallback FAIL");
    if (DobbyHook(xv, (void*)h_x509verify, (void**)&o_x509verify)==0) sc_log("hook x509verify ok");
    else sc_log("hook x509verify FAIL");
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    pthread_t t;
    pthread_create(&t, nullptr, worker, nullptr);
    return JNI_VERSION_1_6;
}
