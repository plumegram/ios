// StandCore iOS — net redirect + TLS pinning bypass (Unity / Mono.Unity)
//
// Порт standcore.cpp с Android на iOS.
//   Android: JNI_OnLoad + libil2cpp.so + /sdcard + __android_log_print
//   iOS:     __attribute__((constructor)) + UnityFramework + app container + stderr/log-файл
//
// Таргет: Standoff 2 iOS 0.22.0 (build 2090), arm64, image = UnityFramework
//
// ВАЖНО (iOS 26, стоковая прошивка): inline-хук системной функции через Dobby
// убивает процесс. Dobby патчит страницу libsystem_kernel, где лежит connect;
// страница становится "грязной", ядро помечает её как invalid page
// (CODESIGNING / Invalid Page), и любое исполнение в этой странице — включая
// соседний __write_nocancel — падает с KERN_PROTECTION_FAILURE.
// Поэтому connect подменяется через dyld interposing (__DATA,__interpose):
// это правка таблицы символов, а не кода, и подпись страниц не трогается.
// Dobby остаётся только для хуков внутри UnityFramework (код приложения).

#include <arpa/inet.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "dobby.h"

// Адрес сервера: можно переопределить при сборке
//   -DSC_SERVER_IP_OVERRIDE="\"1.2.3.4\""
#ifndef SC_SERVER_IP_OVERRIDE
#define SC_SERVER_IP_OVERRIDE "2.26.123.219"
#endif
static const char *const SC_SERVER_IP = SC_SERVER_IP_OVERRIDE;

// ============================ logging ============================
// Порядок важен: сначала файл, потом stderr. Если stderr окажется недоступен
// (например, страница libc испорчена чьим-то патчем), в файле уже будет запись.

static char g_log_path[512] = {0};

static void sc_open_log(void) {
    // на iOS пишем в контейнер приложения: $HOME/Documents/standcore.log
    const char *home = getenv("HOME");
    if (!home) return;
    char docs[480];
    snprintf(docs, sizeof(docs), "%s/Documents", home);
    mkdir(docs, 0755);
    snprintf(g_log_path, sizeof(g_log_path), "%s/standcore.log", docs);
}

static void sc_log(const char *fmt, ...) {
    char msg[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    time_t t = time(nullptr);
    struct tm tmv;
    localtime_r(&t, &tmv);

    char line[896];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d] %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, msg);

    if (g_log_path[0]) {
        FILE *f = fopen(g_log_path, "a");
        if (f) {
            fputs(line, f);
            fclose(f);
        }
    }
    fputs(line, stderr);  // видно в Console.app / idevicesyslog
}

// ============================ connect hook ============================

// адреса, которые НЕ трогаем (google/firebase/telemetry и локалка)
static bool is_private_or_google(uint32_t be_addr) {
    uint32_t a = ntohl(be_addr);
    uint8_t o1 = (a >> 24) & 0xFF, o2 = (a >> 16) & 0xFF;
    if (o1 == 10 || o1 == 127 || o1 == 0) return true;                              // локальные
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return true;
    if (o1 == 192 && o2 == 168) return true;
    if (o1 == 100 && o2 >= 64 && o2 <= 127) return true;                            // CGNAT оператора
    if (o1 == 142 || o1 == 172 || o1 == 216 || o1 == 74 || o1 == 173) return true;  // google-ish
    if (o1 == 34 || o1 == 35) return true;                                          // gcp
    return false;
}

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
static connect_fn sc_orig_connect = nullptr;

static int sc_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!sc_orig_connect) {
        // RTLD_NEXT — следующее определение после нас, то есть настоящий libsystem
        sc_orig_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
        if (!sc_orig_connect) {
            sc_log("не нашёл оригинальный connect");
            return -1;
        }
    }

    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        int port = ntohs(in->sin_port);

        // HTTP/HTTPS не трогаем: обновления, конфиги, аналитика — им нужен настоящий интернет
        if (port == 80 || port == 443 || port == 8080) {
            sc_log("connect %s:%d  (web, пропущен)", ip, port);
            return sc_orig_connect(sockfd, addr, addrlen);
        }
        if (!is_private_or_google(in->sin_addr.s_addr)) {
            struct sockaddr_in patched;
            memcpy(&patched, in, sizeof(patched));
            inet_pton(AF_INET, SC_SERVER_IP, &patched.sin_addr);
            sc_log("connect %s:%d  ->  %s:%d (redirect)", ip, port, SC_SERVER_IP, port);
            return sc_orig_connect(sockfd, (const struct sockaddr *)&patched, addrlen);
        }
        sc_log("connect %s:%d  (пропущен)", ip, port);
    } else if (addr && addr->sa_family == AF_INET6) {
        sc_log("connect ipv6 (пропущен)");
    }
    return sc_orig_connect(sockfd, addr, addrlen);
}

// dyld interposing: dyld сам перенаправит вызовы connect из образов,
// загруженных после нас (главный бинарник + UnityFramework). Код не патчится.
struct sc_interpose_pair {
    const void *replacement;
    const void *original;
};
__attribute__((used, section("__DATA,__interpose")))
static const struct sc_interpose_pair sc_interpose_connect = {
    (const void *)&sc_connect,
    (const void *)&connect,
};

// ============================ TLS pinning bypass ============================

// base = runtime-адрес mach_header нужного образа (slide уже внутри указателя),
// RVA из Il2CppDumper отсчитан от __TEXT vmaddr = 0, поэтому hook = base + RVA.
static uintptr_t sc_image_base(const char *needle) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, needle)) return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

typedef uint32_t (*verify3_t)(void *, void *, void *);
typedef uint32_t (*verify4_t)(void *, void *, uint32_t, void *);

static verify3_t o_VerifyCallback = nullptr;
static verify4_t o_x509verify = nullptr;

static uint32_t h_VerifyCallback(void *u, void *chain, void *err) {
    if (o_VerifyCallback) o_VerifyCallback(u, chain, err);  // дать отработать, но результат перебить
    return 0;                                               // UNITYTLS_X509VERIFY_SUCCESS
}

static uint32_t h_x509verify(void *u, void *cert, uint32_t res, void *err) {
    (void)u; (void)cert; (void)res; (void)err;
    return 0;
}

// RVA для 0.22.0 — из dump_0.22.0/offsets.txt.
// Проверяем пролог: если байты не совпали, версия/бинарь другие -> хук не ставим (иначе краш).
#if defined(__arm64__) || defined(__aarch64__)
static const uintptr_t RVA_VERIFY_CALLBACK = 0x031ADEA4;  // Mono.Unity.UnityTlsContext.VerifyCallback
static const uintptr_t RVA_X509VERIFY = 0x031B0EA4;       // Mono.Unity.UnityTlsProvider.x509verify_callback
static const uint8_t PROLOGUE_VC[8] = {0xff, 0x03, 0x01, 0xd1, 0xf6, 0x57, 0x01, 0xa9};
static const uint8_t PROLOGUE_XV[8] = {0xf6, 0x57, 0xbd, 0xa9, 0xf4, 0x4f, 0x01, 0xa9};
#define SC_HAVE_TLS_RVA 1
#else
#define SC_HAVE_TLS_RVA 0
#endif

static bool prologue_ok(void *addr, const uint8_t *expect) {
    uint8_t got[8];
    memcpy(got, addr, sizeof(got));
    if (memcmp(got, expect, sizeof(got)) == 0) return true;
    sc_log("пролог не совпал @ %p: %02x%02x%02x%02x%02x%02x%02x%02x", addr,
           got[0], got[1], got[2], got[3], got[4], got[5], got[6], got[7]);
    return false;
}

static void install_tls_bypass(void) {
#if SC_HAVE_TLS_RVA
    uintptr_t base = 0;
    for (int i = 0; i < 120 && !base; i++) {  // ~30 c: ждём, пока dyld поднимет UnityFramework
        base = sc_image_base("UnityFramework");
        if (!base) usleep(250000);
    }
    if (!base) {
        sc_log("UnityFramework не найден — pinning не обойдён");
        return;
    }
    sc_log("UnityFramework base=%p", (void *)base);

    void *vc = (void *)(base + RVA_VERIFY_CALLBACK);
    void *xv = (void *)(base + RVA_X509VERIFY);
    sc_log("candidates: VerifyCallback=%p  x509verify=%p", vc, xv);

    if (prologue_ok(vc, PROLOGUE_VC)) {
        if (DobbyHook(vc, (void *)h_VerifyCallback, (void **)&o_VerifyCallback) == 0)
            sc_log("hook VerifyCallback ok");
        else
            sc_log("hook VerifyCallback FAIL");
    } else {
        sc_log("VerifyCallback пропущен (другой билд игры?)");
    }

    if (prologue_ok(xv, PROLOGUE_XV)) {
        if (DobbyHook(xv, (void *)h_x509verify, (void **)&o_x509verify) == 0)
            sc_log("hook x509verify ok");
        else
            sc_log("hook x509verify FAIL");
    } else {
        sc_log("x509verify пропущен (другой билд игры?)");
    }
#else
    sc_log("арх не поддержана для TLS-байпаса");
#endif
}

// ============================ entry ============================

static void *sc_worker(void *) {
    char exe[512] = {0};
    uint32_t sz = sizeof(exe);
    _NSGetExecutablePath(exe, &sz);

    sc_log("=== worker start, pid=%d ===", (int)getpid());
    sc_log("exe=%s", exe);
    sc_log("server=%s", SC_SERVER_IP);
    sc_log("connect подменён через __DATA,__interpose");

#ifdef SC_NO_TLS_HOOK
    sc_log("TLS-хуки отключены при сборке (SC_NO_TLS_HOOK)");
#else
    install_tls_bypass();
#endif
    sc_log("=== init done ===");
    return nullptr;
}

__attribute__((constructor)) static void sc_ctor(void) {
    // конструктор выполняется очень рано: сначала отметка в логе (если процесс
    // умрёт в потоке, будет видно, что dylib всё-таки загрузилась), потом поток
    sc_open_log();
    sc_log("=== StandCore(iOS) ctor, pid=%d ===", (int)getpid());

    pthread_t t;
    if (pthread_create(&t, nullptr, sc_worker, nullptr) == 0) pthread_detach(t);
    else sc_log("не удалось создать поток");
}
