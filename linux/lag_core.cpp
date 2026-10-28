// lag_core.cpp — ядро Lag для Linux: все проверки, отчёты, обновление.
// VERSION = 1.0
// Подключается из lag.cpp (одна единица трансляции, как в Windows-версии).
// Сборка: make (нужны g++ с C++17 и заголовки OpenSSL: libssl-dev / openssl-devel).
// Кодировка исходника — UTF-8.
//
// Логика проверок перенесена из Windows-версии (windows/Lag.cpp) почти без изменений:
// Winsock закрыт тонкой прослойкой совместимости ниже. Системные части
// (интерфейсы, маршруты, DNS, прокси, HTTPS, трассировка, обновление) написаны под Linux.

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/xattr.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>

// ================== ПРОСЛОЙКА WINSOCK -> POSIX ==================
// Перенесённый из Windows код пользуется этими именами; здесь они отображаются на POSIX.
typedef int SOCKET;
#define INVALID_SOCKET (-1)
typedef uint32_t DWORD;
typedef unsigned short u_short;
typedef unsigned long  u_long;

static inline int closesocket(int s) { return ::close(s); }
// ioctlsocket(s, FIONBIO, &nb): включить/выключить неблокирующий режим
static inline int ioctlsocket(int s, unsigned long /*cmd*/, u_long* nb) {
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return -1;
    fl = (*nb) ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
    return fcntl(s, F_SETFL, fl);
}
#define WSAECONNRESET ECONNRESET
#define WSAETIMEDOUT  ETIMEDOUT
// Таймаут recv() по SO_RCVTIMEO в Linux приходит как EAGAIN — приводим к «таймауту», как в Windows.
static inline int WSAGetLastError() {
    int e = errno;
    if (e == EAGAIN || e == EWOULDBLOCK) return ETIMEDOUT;
    return e;
}
static inline void Sleep(unsigned ms) { usleep(ms * 1000u); }
static inline uint64_t GetTickCount64() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
static inline DWORD GetTickCount() { return (DWORD)GetTickCount64(); }
struct SYSTEMTIME { int wYear, wMonth, wDay, wHour, wMinute, wSecond, wMilliseconds, wDayOfWeek; };
static inline void GetLocalTime(SYSTEMTIME* st) {
    time_t t = time(nullptr); struct tm lt; localtime_r(&t, &lt);
    st->wYear = lt.tm_year + 1900; st->wMonth = lt.tm_mon + 1; st->wDay = lt.tm_mday;
    st->wHour = lt.tm_hour; st->wMinute = lt.tm_min; st->wSecond = lt.tm_sec;
    st->wMilliseconds = 0; st->wDayOfWeek = lt.tm_wday;
}
// В Windows таймаут сокета — DWORD в мс, в POSIX — struct timeval.
static inline void setSockTimeoutMs(int s, int ms) {
    timeval tv{ ms / 1000, (ms % 1000) * 1000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// ================== ВЕРСИЯ И ССЫЛКИ ОБНОВЛЕНИЯ ==================
static const std::string SCRIPT_VERSION = "1.0";
// Обновление качает только файлы папки linux/ (не весь репозиторий), собирает и заменяет бинарник.
// База для raw-файлов и список файлов Linux-версии:
static const std::string UPDATE_RAW_BASE =
    "https://raw.githubusercontent.com/Yozmor/lag/refs/heads/main/linux/";
static const char* UPDATE_FILES[] = { "lag.cpp", "lag_core.cpp", "lag_probe.cpp", "lag_tui.cpp", "Makefile" };
// Из какого файла читается строка версии ('VERSION = x.y' в шапке lag_core.cpp).
static const std::string UPDATE_VERSION_URL = UPDATE_RAW_BASE + "lag_core.cpp";

// ================== ГЛОБАЛЬНЫЕ ПУТИ ==================
static std::string g_exePath;     // путь к самой программе
static std::string g_exeDir;      // папка программы
static std::string g_baseDir;     // где лежат Settings/Logs/Tools (папка программы или ~/.local/share/lag)
static std::string g_settingsDir; // списки .txt + config.json
static std::string g_toolsDir;    // NextTrace
static std::string g_logsDir;     // отчёты
static std::string g_configPath;
static std::string g_nexttracePath;

// В Windows-коде строки путей были wide; здесь всё UTF-8, поэтому преобразования — тождество.
static inline std::string toU8(const std::string& s) { return s; }
static inline std::string toW(const std::string& s)  { return s; }

// ================== ВЫВОД / ЛОГ ==================
// Каждая строка проверки уходит в сток экрана (если задан) и в файл отчёта.
// thread_local — у каждого рабочего потока свой сток.
static thread_local std::function<void(const std::string& color, const std::string& text)> g_guiSink;

static void writeLog(const std::string& text, const std::string& color = "White",
                     const std::string& logFile = "") {
    if (g_guiSink) g_guiSink(color, text);
    if (!logFile.empty()) {
        std::ofstream f(logFile, std::ios::app | std::ios::binary);
        if (f) { f << text << "\n"; }
    }
}

// ================== СТРОКОВЫЕ УТИЛИТЫ ==================
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
static bool startsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
static std::string sanitizeName(std::string s) {
    // замена символов, недопустимых в путях (аналог regex '[\\/:*?"<>|]')
    for (char& c : s) {
        if (strchr("\\/:*?\"<>|", c)) c = '_';
    }
    return s;
}

// --- Ширина строки в СИМВОЛАХ UTF-8 (а не байтах): важно для выравнивания кириллицы ---
static size_t dispLen(const std::string& s) {
    size_t n = 0;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) i += 1;
        else if ((c >> 5) == 0x6) i += 2;
        else if ((c >> 4) == 0xE) i += 3;
        else if ((c >> 3) == 0x1E) i += 4;
        else i += 1;
        n++;
    }
    return n;
}
static std::string padRight(const std::string& s, size_t width) {
    size_t l = dispLen(s);
    return (l >= width) ? s : s + std::string(width - l, ' ');
}
// Таблица печатается ПОСТРОЧНО (шапка сразу, строки — по мере готовности),
// поэтому ширины колонок задаём заранее: из заголовков и минимальных ширин.
static std::vector<size_t> tableWidths(const std::vector<std::string>& headers,
                                       const std::vector<size_t>& minW) {
    std::vector<size_t> w(headers.size());
    for (size_t c = 0; c < headers.size(); c++)
        w[c] = std::max(dispLen(headers[c]), (c < minW.size() ? minW[c] : (size_t)0));
    return w;
}
static void tableSep(const std::vector<size_t>& w, const std::string& logFile) {
    std::string sep;
    for (size_t c = 0; c < w.size(); c++) { if (c) sep += "-+-"; sep += std::string(w[c], '-'); }
    writeLog(sep, "Gray", logFile);
}
static void tableHead(const std::vector<std::string>& headers,
                      const std::vector<size_t>& w, const std::string& logFile) {
    std::string head;
    for (size_t c = 0; c < headers.size(); c++) { if (c) head += " | "; head += padRight(headers[c], w[c]); }
    writeLog(head, "Cyan", logFile);
    tableSep(w, logFile);
}
static void tableRow(const std::vector<std::string>& cells, const std::vector<size_t>& w,
                     const std::string& color, const std::string& logFile) {
    std::string line;
    for (size_t c = 0; c < w.size(); c++) { if (c) line += " | "; line += padRight(c < cells.size() ? cells[c] : "", w[c]); }
    writeLog(line, color, logFile);
}

// ================== КОНФИГ ==================
struct Config {
    int ConnectionTimeout = 1500; // мс — таймаут TCP-connect при скане (было 500/200; поднято)
    int BannerTimeout     = 2000; // мс
    int HttpTimeout       = 5;    // сек
    int MaxLogAgeDays     = 180;
    int MaxHops           = 30;
    int SocksPort         = 0;    // SOCKS-порт VPN-клиента; 0 = авто (HTTP-порт прокси - 1, как в v2rayN)
};
static Config g_config;

// Минимальный парсер плоского JSON { "Key": число, ... }
static void loadConfig() {
    std::ifstream f(g_configPath, std::ios::binary);
    if (!f) { // создаём с дефолтами
        std::ofstream o(g_configPath, std::ios::binary);
        o << "{\n"
          << "  \"ConnectionTimeout\": " << g_config.ConnectionTimeout << ",\n"
          << "  \"BannerTimeout\": "     << g_config.BannerTimeout     << ",\n"
          << "  \"HttpTimeout\": "       << g_config.HttpTimeout       << ",\n"
          << "  \"MaxLogAgeDays\": "     << g_config.MaxLogAgeDays     << ",\n"
          << "  \"MaxHops\": "           << g_config.MaxHops           << ",\n"
          << "  \"SocksPort\": "         << g_config.SocksPort         << "\n}\n";
        return;
    }
    std::stringstream ss; ss << f.rdbuf();
    std::string data = ss.str();
    auto getInt = [&](const std::string& key, int def) -> int {
        std::regex re("\"" + key + "\"\\s*:\\s*(-?\\d+)");
        std::smatch m;
        if (std::regex_search(data, m, re)) { try { return std::stoi(m[1]); } catch (...) {} }
        return def;
    };
    g_config.ConnectionTimeout = getInt("ConnectionTimeout", g_config.ConnectionTimeout);
    g_config.BannerTimeout     = getInt("BannerTimeout",     g_config.BannerTimeout);
    g_config.HttpTimeout       = getInt("HttpTimeout",       g_config.HttpTimeout);
    g_config.MaxLogAgeDays     = getInt("MaxLogAgeDays",     g_config.MaxLogAgeDays);
    g_config.MaxHops           = getInt("MaxHops",           g_config.MaxHops);
    g_config.SocksPort         = getInt("SocksPort",         g_config.SocksPort);
}
static void saveConfig() {
    std::ofstream o(g_configPath, std::ios::binary);
    o << "{\n"
      << "  \"ConnectionTimeout\": " << g_config.ConnectionTimeout << ",\n"
      << "  \"BannerTimeout\": "     << g_config.BannerTimeout     << ",\n"
      << "  \"HttpTimeout\": "       << g_config.HttpTimeout       << ",\n"
      << "  \"MaxLogAgeDays\": "     << g_config.MaxLogAgeDays     << ",\n"
      << "  \"MaxHops\": "           << g_config.MaxHops           << ",\n"
      << "  \"SocksPort\": "         << g_config.SocksPort         << "\n}\n";
    writeLog("Настройки сохранены в config.json", "Gray");
}

// ================== СПИСКИ ИЗ ФАЙЛОВ ==================
struct Item { std::string Value; std::string Comment; };
static bool runBlockProbe(const std::string& logFile, const std::vector<Item>& targets);
static std::vector<Item> loadItemList(const std::string& fileName,
                                      const std::string& headerComment =
                                      "# Список целей\r\n# Формат: значение;комментарий") {
    std::string path = g_settingsDir + "/" + fileName;
    std::vector<Item> result;
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::ofstream o(path, std::ios::binary);
        o << headerComment << "\r\n";
        writeLog("Создан " + toU8(fileName) + ". Добавьте данные и перезапустите.", "Yellow");
        return result;
    }
    std::string line;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        size_t p = t.find(';');
        Item it;
        it.Value   = (p == std::string::npos) ? t : trim(t.substr(0, p));
        it.Comment = (p == std::string::npos) ? "" : trim(t.substr(p + 1));
        if (!it.Value.empty()) result.push_back(it);
    }
    if (result.empty())
        writeLog("Файл '" + toU8(fileName) + "' пуст", "Yellow");
    return result;
}

static std::string resolveIPv4(const std::string& host) {
    in_addr tmp;
    if (inet_pton(AF_INET, host.c_str(), &tmp) == 1) return host;
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string ip;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
        char b[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, b, sizeof(b));
        ip = b;
        freeaddrinfo(res);
    }
    return ip;
}

static bool ipIsSpecial(const in_addr& a) {
    unsigned char b0 = ((const unsigned char*)&a)[0], b1 = ((const unsigned char*)&a)[1];
    if (a.s_addr == 0 || a.s_addr == 0xFFFFFFFF) return true;   // 0.0.0.0, 255.255.255.255
    if (b0 == 127) return true;                                  // loopback
    if (b0 >= 224) return true;                                  // multicast и выше
    if (b0 == 169 && b1 == 254) return true;                     // link-local
    return false;
}

static SOCKET connectTcp(const std::string& ip, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port);
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) { closesocket(s); return INVALID_SOCKET; }
    connect(s, (sockaddr*)&sa, sizeof(sa));
    fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
    timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
    bool ok = false;
    if (select(s + 1, nullptr, &wf, nullptr, &tv) > 0) {
        int err = 0; socklen_t len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        ok = (err == 0);
    }
    if (!ok) { closesocket(s); return INVALID_SOCKET; }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    setSockTimeoutMs(s, timeoutMs);
    return s;
}
static bool recvExact(SOCKET s, unsigned char* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}
// "127.0.0.1:10809" или "http=127.0.0.1:10809;https=..." -> host, port
static bool parseProxyAddr(const std::string& proxyW, std::string& host, int& port) {
    std::string p = toU8(proxyW);
    size_t eq = p.find("http=");
    if (eq != std::string::npos) {
        p = p.substr(eq + 5);
        size_t sc = p.find(';'); if (sc != std::string::npos) p = p.substr(0, sc);
    } else if (p.find('=') != std::string::npos) {
        p = p.substr(p.find('=') + 1);
        size_t sc = p.find(';'); if (sc != std::string::npos) p = p.substr(0, sc);
    }
    size_t sch = p.find("://"); if (sch != std::string::npos) p = p.substr(sch + 3);
    size_t c = p.rfind(':');
    if (c == std::string::npos) return false;
    host = trim(p.substr(0, c));
    try { port = std::stoi(p.substr(c + 1)); } catch (...) { return false; }
    if (host == "localhost") host = "127.0.0.1";
    return !host.empty() && port > 0 && port < 65536;
}
struct ProbeResult { bool portOpen = false, protoOk = false, tunnelOk = false; long ms = 0; std::string note; };
static const char* PROBE_HOST = "www.google.com";
static const int   PROBE_PORT = 443;

// HTTP-прокси: CONNECT www.google.com:443 -> ждём "HTTP/1.x 200".
static ProbeResult probeHttpProxy(const std::string& host, int port, int timeoutMs) {
    ProbeResult pr;
    SOCKET s = connectTcp(host, port, timeoutMs);
    if (s == INVALID_SOCKET) return pr;
    pr.portOpen = true;
    auto t0 = std::chrono::steady_clock::now();
    std::string req = std::string("CONNECT ") + PROBE_HOST + ":" + std::to_string(PROBE_PORT) +
                      " HTTP/1.1\r\nHost: " + PROBE_HOST + ":" + std::to_string(PROBE_PORT) + "\r\n\r\n";
    send(s, req.c_str(), (int)req.size(), 0);
    char buf[512]; int n = recv(s, buf, sizeof(buf) - 1, 0);
    pr.ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
    if (n > 0) {
        buf[n] = 0;
        std::string line(buf);
        line = line.substr(0, line.find("\r\n"));
        if (startsWith(line, "HTTP/")) {
            pr.protoOk = true;
            std::smatch m;
            if (std::regex_search(line, m, std::regex("HTTP/\\d\\.\\d\\s+(\\d{3})"))) {
                pr.tunnelOk = (m[1] == "200");
                if (!pr.tunnelOk) pr.note = "ответ " + std::string(m[1]);
            }
        } else pr.note = "ответ не похож на HTTP";
    } else pr.note = "нет ответа на CONNECT";
    closesocket(s);
    return pr;
}
// SOCKS5: приветствие 05 01 00 -> 05 00, затем CONNECT www.google.com:443 -> 05 00 ...
static ProbeResult probeSocks5(const std::string& host, int port, int timeoutMs) {
    ProbeResult pr;
    SOCKET s = connectTcp(host, port, timeoutMs);
    if (s == INVALID_SOCKET) return pr;
    pr.portOpen = true;
    unsigned char hello[3] = { 0x05, 0x01, 0x00 };
    send(s, (const char*)hello, 3, 0);
    unsigned char rep[2];
    if (!recvExact(s, rep, 2) || rep[0] != 0x05) { pr.note = "не SOCKS5"; closesocket(s); return pr; }
    if (rep[1] == 0xFF) { pr.protoOk = true; pr.note = "требует логин/пароль"; closesocket(s); return pr; }
    if (rep[1] != 0x00) { pr.protoOk = true; pr.note = "метод авторизации " + std::to_string(rep[1]); closesocket(s); return pr; }
    pr.protoOk = true;

    auto t0 = std::chrono::steady_clock::now();
    std::vector<unsigned char> req = { 0x05, 0x01, 0x00, 0x03 };
    std::string h = PROBE_HOST;
    req.push_back((unsigned char)h.size());
    for (char c : h) req.push_back((unsigned char)c);
    req.push_back((unsigned char)(PROBE_PORT >> 8));
    req.push_back((unsigned char)(PROBE_PORT & 0xFF));
    send(s, (const char*)req.data(), (int)req.size(), 0);
    unsigned char ans[2];
    if (recvExact(s, ans, 2)) {
        pr.ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
        if (ans[1] == 0x00) pr.tunnelOk = true;
        else pr.note = "CONNECT отклонён, код " + std::to_string(ans[1]);
    } else pr.note = "нет ответа на CONNECT";
    closesocket(s);
    return pr;
}
static void printProbe(const std::string& label, const std::string& addr,
                       const ProbeResult& pr, bool missingIsProblem, const std::string& logFile) {
    std::string head = padRight(label, 7) + padRight(addr, 18);
    if (!pr.portOpen) {
        if (missingIsProblem) writeLog(head + "закрыт / не отвечает   [ПРОБЛЕМА]", "Red", logFile);
        else writeLog(head + "закрыт (не включён или другой порт — задай SocksPort в config.json)", "Gray", logFile);
    } else if (!pr.protoOk) {
        writeLog(head + "открыт, но это не прокси (" + pr.note + ")", "Yellow", logFile);
    } else if (!pr.tunnelOk) {
        writeLog(head + "отвечает, но выход в интернет не прошёл (" + pr.note + ")   [ПРОБЛЕМА]", "Red", logFile);
    } else {
        writeLog(head + "отвечает, CONNECT до " + PROBE_HOST + " OK (" + std::to_string(pr.ms) + " мс)   [OK]",
                 "Green", logFile);
    }
}

// ================== МАШИНОЧИТАЕМЫЙ ОТЧЁТ (JSON) ==================
// Снимок нейтрального состояния сети/VPN рядом с текстовым отчётом netstate.
// Только факты: режим, внешний IP/страна, порты прокси, адаптеры, DNS, обходные маршруты.
// Вердикта о типе блокировки здесь нет и не предполагается.
static std::string jsonEsc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
                else o += (char)c;   // UTF-8 проходит как есть
        }
    }
    return o;
}
static std::string jStr(const std::string& s) { return "\"" + jsonEsc(s) + "\""; }

// ================== СИСТЕМНЫЕ МЕЛОЧИ (Linux) ==================
static std::string readFileAll(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}
static bool pathExists(const std::string& p) { struct stat st; return stat(p.c_str(), &st) == 0; }
static bool isDir(const std::string& p) { struct stat st; return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode); }
// Короткий запуск команды с перехватом stdout (stderr глушим в самой команде).
static std::string runCmd(const std::string& cmd, size_t maxBytes = 65536) {
    std::string out;
    FILE* p = popen((cmd + " </dev/null").c_str(), "r");
    if (!p) return out;
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0) {
        out.append(buf, n);
        if (out.size() > maxBytes) break;
    }
    pclose(p);
    return out;
}
static bool haveCmd(const std::string& name) {
    std::string r = runCmd("command -v " + name + " 2>/dev/null");
    return !trim(r).empty();
}
static std::string shellQuote(const std::string& s) {
    std::string o = "'";
    for (char c : s) { if (c == '\'') o += "'\\''"; else o += c; }
    return o + "'";
}

// ================== ОПРЕДЕЛЕНИЕ ТИПА ПОДКЛЮЧЕНИЯ + VPN ==================
struct ConnInfo {
    std::string BaseType = "Неизвестно";
    std::string Detail   = "-";
    std::string VpnName;
    bool VpnActive = false;
    std::string FullString;
    std::string LinkSpeed;
};

// Интерфейс туннельный? tun/tap имеют tun_flags, WireGuard и tun — тип 65534 (ARPHRD_NONE),
// GRE/IPIP/SIT/PPP — свои типы. Плюс имена популярных VPN-клиентов.
static bool ifIsTunnel(const std::string& ifn) {
    std::string base = "/sys/class/net/" + ifn;
    if (pathExists(base + "/tun_flags")) return true;
    std::string ty = trim(readFileAll(base + "/type"));
    static const std::set<std::string> tunTypes = { "65534", "512", "768", "769", "776", "778", "823" };
    if (tunTypes.count(ty)) return true;
    std::string low = ifn; for (auto& c : low) c = (char)tolower((unsigned char)c);
    static const char* pre[] = { "tun", "tap", "wg", "utun", "ppp", "tailscale", "zt", "nekoray", "sing",
                                 "xray", "clash", "meta", "hiddify", "amn", "awg", "outline", "proton",
                                 "nordlynx", "mullvad", "vpn", "ygg" };
    for (auto p : pre) if (low.rfind(p, 0) == 0) return true;
    return false;
}
static bool ifIsWireless(const std::string& ifn) {
    return pathExists("/sys/class/net/" + ifn + "/wireless") || pathExists("/sys/class/net/" + ifn + "/phy80211");
}
static std::string ifTypeOf(const std::string& ifn) {
    std::string ty = trim(readFileAll("/sys/class/net/" + ifn + "/type"));
    if (ifn == "lo" || ty == "772") return "Loopback";
    if (ifIsWireless(ifn)) return "Wi-Fi";
    if (ty == "512") return "PPP";
    if (ifIsTunnel(ifn)) return "Туннель";
    return "Ethernet";
}

// /proc/net/route — основная таблица маршрутов IPv4.
// Числа там — u32 в порядке байт сети, распечатанные как hex: годятся напрямую в in_addr.s_addr.
struct RouteRow { std::string iface; uint32_t dst = 0, gw = 0, mask = 0; int metric = 0; int prefix = 0; };
static std::vector<RouteRow> readRoutes() {
    std::vector<RouteRow> out;
    std::istringstream in(readFileAll("/proc/net/route"));
    std::string line; std::getline(in, line);   // заголовок
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string ifn, dst, gw, flags, ref, use, metric, mask;
        if (!(ls >> ifn >> dst >> gw >> flags >> ref >> use >> metric >> mask)) continue;
        RouteRow r; r.iface = ifn;
        r.dst = (uint32_t)strtoul(dst.c_str(), nullptr, 16);
        r.gw = (uint32_t)strtoul(gw.c_str(), nullptr, 16);
        r.mask = (uint32_t)strtoul(mask.c_str(), nullptr, 16);
        r.metric = atoi(metric.c_str());
        r.prefix = __builtin_popcount(r.mask);
        out.push_back(r);
    }
    return out;
}

// ================== ИНТЕРФЕЙСЫ И МАРШРУТЫ ==================
struct AdapterInfo {
    DWORD ifIndex = 0;
    std::string name, desc, ipv4, type;
    bool vpnLike = false, hasGw = false;
};
// Активные (Up) IPv4-интерфейсы системы.
static std::vector<AdapterInfo> listAdapters() {
    std::vector<AdapterInfo> out;
    auto routes = readRoutes();
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) != 0) return out;
    for (ifaddrs* a = ifa; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET) continue;
        if (!(a->ifa_flags & IFF_UP)) continue;
        AdapterInfo ai;
        ai.name = a->ifa_name;
        ai.ifIndex = if_nametoindex(a->ifa_name);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((sockaddr_in*)a->ifa_addr)->sin_addr, ip, sizeof(ip));
        ai.ipv4 = ip;
        ai.type = ifTypeOf(ai.name);
        ai.vpnLike = (ai.type == "Туннель" || ai.type == "PPP");
        for (auto& r : routes) if (r.iface == ai.name && r.gw != 0) { ai.hasGw = true; break; }
        bool dup = false;
        for (auto& x : out) if (x.name == ai.name) { dup = true; break; }
        if (!dup) out.push_back(ai);
    }
    freeifaddrs(ifa);
    return out;
}
static std::string ifaceByLocalIp(const std::string& lip) {
    for (auto& a : listAdapters()) if (a.ipv4 == lip) return a.name;
    return "";
}

struct RouteInfo {
    bool ok = false;
    std::string ip, ifName, ifType, localIp, err;
    bool viaTunnel = false;
};
// Через какой интерфейс ОС отправит пакет до host. UDP connect() ничего не отправляет,
// но ядро выбирает маршрут с учётом policy routing (ip rule) — так видно и sing-box/wg-quick.
static RouteInfo routeTo(const std::string& host) {
    RouteInfo r;
    r.ip = resolveIPv4(host);
    if (r.ip.empty()) { r.err = "не резолвится"; return r; }
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(53);
    inet_pton(AF_INET, r.ip.c_str(), &sa.sin_addr);
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) { r.err = "нет сокета"; return r; }
    if (connect(s, (sockaddr*)&sa, sizeof(sa)) != 0) { closesocket(s); r.err = "нет маршрута"; return r; }
    sockaddr_in loc{}; socklen_t len = sizeof(loc);
    if (getsockname(s, (sockaddr*)&loc, &len) == 0) {
        char b[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &loc.sin_addr, b, sizeof(b)); r.localIp = b;
    }
    closesocket(s);
    r.ifName = ifaceByLocalIp(r.localIp);
    if (r.ifName.empty()) r.ifName = "?";
    else { r.ifType = ifTypeOf(r.ifName); r.viaTunnel = ifIsTunnel(r.ifName); }
    r.ok = true;
    return r;
}

// DNS-серверы, которыми реально пользуется система.
struct DnsServer { std::string ip, adapter; };
static void parseResolv(const std::string& path, const std::string& label, std::vector<DnsServer>& out) {
    std::istringstream in(readFileAll(path));
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ls(line); std::string k, v;
        if (!(ls >> k >> v) || k != "nameserver") continue;
        in_addr ia;
        if (inet_pton(AF_INET, v.c_str(), &ia) != 1) continue;   // только IPv4
        bool dup = false; for (auto& x : out) if (x.ip == v) { dup = true; break; }
        if (!dup) out.push_back({ v, label });
    }
}
static std::vector<DnsServer> listDnsServers() {
    std::vector<DnsServer> out;
    parseResolv("/etc/resolv.conf", "resolv.conf", out);
    // systemd-resolved: в resolv.conf только заглушка 127.0.0.53, настоящие серверы — тут
    bool stub = false; for (auto& d : out) if (d.ip == "127.0.0.53" || d.ip == "127.0.0.54") stub = true;
    if (stub) parseResolv("/run/systemd/resolve/resolv.conf", "systemd-resolved", out);
    return out;
}
// Системный DNS (первый IPv4) — для теста DNS
static std::string getSystemDns() {
    auto d = listDnsServers();
    return d.empty() ? "" : d[0].ip;
}
// Обходные маршруты: отдельные адреса (/32) через шлюз физического интерфейса.
// В TUN-режиме VPN-клиент так выводит из туннеля адрес своего сервера.
static std::vector<std::string> listBypassRoutes() {
    std::vector<std::string> out;
    for (auto& r : readRoutes()) {
        if (r.prefix != 32 || r.gw == 0 || ifIsTunnel(r.iface)) continue;
        in_addr dst; dst.s_addr = r.dst;
        if (ipIsSpecial(dst)) continue;
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &dst, ip, sizeof(ip));
        if (std::find(out.begin(), out.end(), std::string(ip)) == out.end()) out.push_back(ip);
    }
    return out;
}
// Туннель реально несёт трафик, если ему принадлежит маршрут по умолчанию.
// 1) основная таблица: сплит 0.0.0.0/1 + 128.0.0.0/1 (подпись TUN-клиентов) или дефолт на туннеле;
// 2) policy routing (sing-box auto_route, wg-quick): смотрим, куда ядро реально шлёт пакеты
//    к нескольким обычным адресам. DNS-адреса не берём — их клиенты часто пускают в обход.
// Yggdrasil сюда не попадает: он держит только свою IPv6-сеть, IPv4-дефолт не трогает.
static bool defaultViaTunnel() {
    for (auto& r : readRoutes()) {
        if (r.prefix == 1) return true;
        if (r.prefix == 0 && ifIsTunnel(r.iface)) return true;
    }
    for (const char* ip : { "151.101.1.1", "104.16.1.1", "23.62.1.1" }) {
        RouteInfo ri = routeTo(ip);
        if (ri.ok && ri.viaTunnel) return true;
    }
    return false;
}

static std::string getWifiSsid(const std::string& ifn) {
    std::string s;
    if (haveCmd("iwgetid")) s = trim(runCmd("iwgetid -r " + shellQuote(ifn) + " 2>/dev/null"));
    if (s.empty() && haveCmd("nmcli")) {
        std::istringstream in(runCmd("nmcli -t -f active,ssid dev wifi 2>/dev/null"));
        std::string line;
        while (std::getline(in, line)) if (startsWith(line, "yes:")) { s = trim(line.substr(4)); break; }
    }
    return s;
}
static std::string getLinkSpeed(const std::string& ifn, bool wifi) {
    if (wifi) {
        if (!haveCmd("iw")) return "";
        std::string o = runCmd("iw dev " + shellQuote(ifn) + " link 2>/dev/null");
        std::smatch m;
        if (std::regex_search(o, m, std::regex("tx bitrate:\\s*([0-9.]+)\\s*MBit/s")))
            return std::to_string((long)atof(std::string(m[1]).c_str())) + " Mbps";
        return "";
    }
    long sp = atol(trim(readFileAll("/sys/class/net/" + ifn + "/speed")).c_str());
    return sp > 0 ? std::to_string(sp) + " Mbps" : "";
}
// Основной физический интерфейс: маршрут по умолчанию не через туннель, минимальная метрика.
static std::string physicalDefaultIface() {
    std::string best; int bm = INT_MAX;
    for (auto& r : readRoutes())
        if (r.prefix == 0 && !ifIsTunnel(r.iface) && r.metric < bm) { bm = r.metric; best = r.iface; }
    return best;
}
static ConnInfo getConnectionType() {
    ConnInfo r;
    for (auto& a : listAdapters())
        if (a.vpnLike) { r.VpnActive = true; r.VpnName = sanitizeName(a.name); break; }
    std::string ifn = physicalDefaultIface();
    if (!ifn.empty()) {
        bool wifi = ifIsWireless(ifn);
        r.BaseType = wifi ? "Wi-Fi" : "Ethernet";
        std::string ssid = wifi ? getWifiSsid(ifn) : "";
        r.Detail = sanitizeName(ssid.empty() ? ifn : ssid);
        r.LinkSpeed = getLinkSpeed(ifn, wifi);
    }
    r.FullString = r.BaseType + "_" + r.Detail;
    if (r.VpnActive) r.FullString += "+VPN_" + r.VpnName;
    r.FullString = sanitizeName(r.FullString);
    return r;
}

// ================== ПУТЬ К ЛОГУ + ОЧИСТКА ==================
static void ensureDirRec(const std::string& d) {
    for (size_t i = 1; i < d.size(); i++)
        if (d[i] == '/') mkdir(d.substr(0, i).c_str(), 0755);
    mkdir(d.c_str(), 0755);
}
static std::string nowStamp() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[64];
    snprintf(b, sizeof(b), "%04d-%02d-%02d_%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}
static std::string getLogFilePath(const std::string& folderKey) {
    ConnInfo ci = getConnectionType();
    std::string target = g_logsDir + "/" + (ci.FullString.empty() ? "Unknown" : ci.FullString) + "/" + folderKey;
    ensureDirRec(target);
    return target + "/" + nowStamp() + ".txt";
}
static void removeOldLogs() {
    if (!isDir(g_logsDir) || g_config.MaxLogAgeDays <= 0) return;
    time_t cutoff = time(nullptr) - (time_t)g_config.MaxLogAgeDays * 86400;
    int removed = 0;
    std::vector<std::string> stack{ g_logsDir };
    while (!stack.empty()) {
        std::string dir = stack.back(); stack.pop_back();
        DIR* d = opendir(dir.c_str());
        if (!d) continue;
        while (dirent* e = readdir(d)) {
            std::string name = e->d_name;
            if (name == "." || name == "..") continue;
            std::string full = dir + "/" + name;
            struct stat st;
            if (stat(full.c_str(), &st) != 0) continue;
            if (S_ISDIR(st.st_mode)) { stack.push_back(full); continue; }
            if (st.st_mtime < cutoff && unlink(full.c_str()) == 0) removed++;
        }
        closedir(d);
    }
    if (removed > 0)
        writeLog("Очищено " + std::to_string(removed) + " старых логов (старше " +
                 std::to_string(g_config.MaxLogAgeDays) + " дней).", "Gray");
}

// ================== СИСТЕМНЫЙ ПРОКСИ ==================
// В Linux единого «системного прокси» нет. Смотрим то, чем пользуются браузеры и VPN-клиенты:
// переменные окружения, настройки GNOME (gsettings) и KDE (kioslaverc).
// Результат: "http://host:port" или "socks5://host:port", пусто — прокси нет.
static std::string detectSystemProxy() {
    for (const char* n : { "https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY" }) {
        const char* v = getenv(n);
        if (v && *v) { std::string s = trim(v); while (!s.empty() && s.back() == '/') s.pop_back(); return s; }
    }
    if (haveCmd("gsettings")) {
        std::string mode = runCmd("gsettings get org.gnome.system.proxy mode 2>/dev/null");
        if (mode.find("manual") != std::string::npos) {
            auto get = [](const std::string& schema, const std::string& key) {
                std::string v = trim(runCmd("gsettings get " + schema + " " + key + " 2>/dev/null"));
                if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'') v = v.substr(1, v.size() - 2);
                return v;
            };
            std::string h = get("org.gnome.system.proxy.http", "host");
            int p = atoi(get("org.gnome.system.proxy.http", "port").c_str());
            if (!h.empty() && p > 0) return "http://" + h + ":" + std::to_string(p);
            h = get("org.gnome.system.proxy.socks", "host");
            p = atoi(get("org.gnome.system.proxy.socks", "port").c_str());
            if (!h.empty() && p > 0) return "socks5://" + h + ":" + std::to_string(p);
        }
    }
    const char* home = getenv("HOME");
    if (home) {
        std::string k = readFileAll(std::string(home) + "/.config/kioslaverc");
        std::smatch m;
        if (std::regex_search(k, m, std::regex("ProxyType=1"))) {
            // httpProxy=http://127.0.0.1 10809   (KDE пишет порт через пробел)
            if (std::regex_search(k, m, std::regex("httpProxy=(?:https?://)?([^\\s:]+)[\\s:]+(\\d+)")))
                return "http://" + std::string(m[1]) + ":" + std::string(m[2]);
            if (std::regex_search(k, m, std::regex("socksProxy=(?:socks5?://)?([^\\s:]+)[\\s:]+(\\d+)")))
                return "socks5://" + std::string(m[1]) + ":" + std::string(m[2]);
        }
    }
    return "";
}
// gsettings запускать на каждый чих дорого — кэшируем на несколько секунд.
static std::string getSystemProxy() {
    static std::mutex mx; static std::string cached; static uint64_t at = 0;
    std::lock_guard<std::mutex> lk(mx);
    uint64_t now = GetTickCount64();
    if (at == 0 || now - at > 5000) { cached = detectSystemProxy(); at = now; }
    return cached;
}
// Имя из Windows-кода: там это прокси из настроек IE.
static std::string getIEProxy() { return getSystemProxy(); }
static bool proxyIsSocks(const std::string& p) { return p.rfind("socks", 0) == 0; }

// ================== HTTP(S) НА OPENSSL ==================
struct UrlParts { std::string host, path; int port = 443; bool secure = true; };
static UrlParts parseUrl(const std::string& raw) {
    std::string u = raw;
    if (!startsWith(u, "http")) u = "https://" + u;
    UrlParts p; p.secure = startsWith(u, "https");
    std::string rest = u.substr(u.find("://") + 3);
    size_t sl = rest.find('/');
    std::string hostport = (sl == std::string::npos) ? rest : rest.substr(0, sl);
    p.path = (sl == std::string::npos) ? "/" : rest.substr(sl);
    p.port = p.secure ? 443 : 80;
    size_t c = hostport.rfind(':');
    if (c != std::string::npos && hostport.find(']') == std::string::npos) {
        p.port = atoi(hostport.substr(c + 1).c_str());
        p.host = hostport.substr(0, c);
    } else p.host = hostport;
    return p;
}
struct HttpResult { int code; long ms; bool ok; std::string body; };

// TCP до хоста по имени: пробуем все его IPv4 по очереди.
static int tcpToHost(const std::string& host, int port, int timeoutMs) {
    in_addr tmp;
    if (inet_pton(AF_INET, host.c_str(), &tmp) == 1) return connectTcp(host, port, timeoutMs);
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return INVALID_SOCKET;
    int s = INVALID_SOCKET;
    for (addrinfo* a = res; a && s == INVALID_SOCKET; a = a->ai_next) {
        char b[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((sockaddr_in*)a->ai_addr)->sin_addr, b, sizeof(b));
        s = connectTcp(b, port, timeoutMs);
    }
    freeaddrinfo(res);
    return s;
}
// Соединение до host:port — напрямую или через прокси (HTTP CONNECT / SOCKS5, имя резолвит прокси).
static int openTunnel(const std::string& host, int port, int timeoutMs, const std::string& proxy) {
    if (proxy.empty()) return tcpToHost(host, port, timeoutMs);
    std::string ph; int pp = 0;
    if (!parseProxyAddr(proxy, ph, pp)) return INVALID_SOCKET;
    int s = tcpToHost(ph, pp, timeoutMs);
    if (s == INVALID_SOCKET) return s;
    if (proxyIsSocks(proxy)) {
        unsigned char hello[3] = { 0x05, 0x01, 0x00 }, rep[2];
        if (send(s, (const char*)hello, 3, 0) != 3 || !recvExact(s, rep, 2) || rep[0] != 5 || rep[1] != 0) {
            closesocket(s); return INVALID_SOCKET;
        }
        std::vector<unsigned char> req = { 0x05, 0x01, 0x00, 0x03, (unsigned char)host.size() };
        for (char c : host) req.push_back((unsigned char)c);
        req.push_back((unsigned char)(port >> 8)); req.push_back((unsigned char)(port & 0xFF));
        send(s, (const char*)req.data(), (int)req.size(), 0);
        unsigned char h[4];
        if (!recvExact(s, h, 4) || h[1] != 0) { closesocket(s); return INVALID_SOCKET; }
        int skip = (h[3] == 1) ? 4 : (h[3] == 4) ? 16 : 0;
        if (h[3] == 3) { unsigned char l; if (!recvExact(s, &l, 1)) { closesocket(s); return INVALID_SOCKET; } skip = l; }
        std::vector<unsigned char> tail(skip + 2);
        if (!recvExact(s, tail.data(), (int)tail.size())) { closesocket(s); return INVALID_SOCKET; }
        return s;
    }
    std::string req = "CONNECT " + host + ":" + std::to_string(port) + " HTTP/1.1\r\nHost: " +
                      host + ":" + std::to_string(port) + "\r\n\r\n";
    send(s, req.c_str(), (int)req.size(), 0);
    std::string resp; char c;
    while (resp.size() < 8192 && recv(s, &c, 1, 0) == 1) {
        resp += c;
        if (resp.size() >= 4 && resp.compare(resp.size() - 4, 4, "\r\n\r\n") == 0) break;
    }
    std::smatch m;
    if (!std::regex_search(resp, m, std::regex("^HTTP/\\d\\.\\d\\s+200"))) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

static SSL_CTX* sslCtx(bool verify) {
    static std::once_flag once;
    static SSL_CTX* ctxVerify = nullptr;
    static SSL_CTX* ctxNoVerify = nullptr;
    std::call_once(once, [] {
        ctxVerify = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_default_verify_paths(ctxVerify);
        SSL_CTX_set_verify(ctxVerify, SSL_VERIFY_PEER, nullptr);
        ctxNoVerify = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ctxNoVerify, SSL_VERIFY_NONE, nullptr);   // как curl -k в Windows-версии
    });
    return verify ? ctxVerify : ctxNoVerify;
}
// Поток поверх сокета: TLS или открытый.
struct Stream {
    int fd = INVALID_SOCKET; SSL* ssl = nullptr;
    int rd(char* b, int n) { return ssl ? SSL_read(ssl, b, n) : (int)recv(fd, b, n, 0); }
    bool wr(const std::string& d) {
        size_t off = 0;
        while (off < d.size()) {
            int w = ssl ? SSL_write(ssl, d.data() + off, (int)(d.size() - off))
                        : (int)send(fd, d.data() + off, d.size() - off, MSG_NOSIGNAL);
            if (w <= 0) return false;
            off += (size_t)w;
        }
        return true;
    }
    void close() {
        if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = nullptr; }
        if (fd != INVALID_SOCKET) { closesocket(fd); fd = INVALID_SOCKET; }
    }
};
static std::string dechunk(const std::string& in) {
    std::string out; size_t p = 0;
    while (p < in.size()) {
        size_t e = in.find("\r\n", p);
        if (e == std::string::npos) break;
        long n = strtol(in.substr(p, e - p).c_str(), nullptr, 16);
        if (n <= 0) break;
        p = e + 2;
        if (p + (size_t)n > in.size()) { out += in.substr(p); break; }
        out += in.substr(p, (size_t)n);
        p += (size_t)n + 2;
    }
    return out;
}
static std::string headerValue(const std::string& head, const std::string& name) {
    std::smatch m;
    if (std::regex_search(head, m, std::regex("\r\n" + name + ":\\s*([^\r\n]*)", std::regex::icase)))
        return trim(m[1]);
    return "";
}
// Полный HTTP(S)-запрос: прокси, редиректы, chunked. verify — проверять сертификат
// (для скачиваний да, для проверок доступности нет — как в Windows-версии).
static HttpResult httpRequestEx(const std::string& url, const std::string& method, int timeoutSec,
                                const std::string& proxy, bool wantBody, bool verify,
                                size_t maxBody = 8u << 20, int redirects = 5) {
    HttpResult res{ 0, 0, false, "" };
    UrlParts u = parseUrl(url);
    auto t0 = std::chrono::steady_clock::now();
    int toMs = std::max(1, timeoutSec) * 1000;
    Stream st;
    st.fd = openTunnel(u.host, u.port, toMs, proxy);
    if (st.fd == INVALID_SOCKET) return res;
    setSockTimeoutMs(st.fd, toMs);
    if (u.secure) {
        st.ssl = SSL_new(sslCtx(verify));
        SSL_set_fd(st.ssl, st.fd);
        in_addr tmp;
        if (inet_pton(AF_INET, u.host.c_str(), &tmp) != 1) SSL_set_tlsext_host_name(st.ssl, u.host.c_str());
        if (verify) SSL_set1_host(st.ssl, u.host.c_str());
        if (SSL_connect(st.ssl) != 1) { st.close(); return res; }
    }
    std::string hostHdr = u.host;
    if ((u.secure && u.port != 443) || (!u.secure && u.port != 80)) hostHdr += ":" + std::to_string(u.port);
    std::string req = method + " " + u.path + " HTTP/1.1\r\nHost: " + hostHdr +
                      "\r\nUser-Agent: Lag/" + SCRIPT_VERSION + " (Linux)\r\nAccept: */*\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n\r\n";
    if (!st.wr(req)) { st.close(); return res; }

    std::string data; char buf[16384];
    size_t hEnd = std::string::npos;
    while (hEnd == std::string::npos) {
        int n = st.rd(buf, sizeof(buf));
        if (n <= 0) break;
        data.append(buf, n);
        hEnd = data.find("\r\n\r\n");
        if (data.size() > 65536 && hEnd == std::string::npos) break;
    }
    if (hEnd == std::string::npos) { st.close(); return res; }
    std::string head = data.substr(0, hEnd + 2);
    std::smatch m;
    if (!std::regex_search(head, m, std::regex("^HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})"))) { st.close(); return res; }
    res.code = atoi(std::string(m[1]).c_str());
    res.ok = true;
    res.ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - t0).count();

    if (res.code >= 300 && res.code < 400 && redirects > 0) {
        std::string loc = headerValue(head, "Location");
        if (!loc.empty()) {
            st.close();
            if (startsWith(loc, "//")) loc = (u.secure ? "https:" : "http:") + loc;
            else if (startsWith(loc, "/"))
                loc = std::string(u.secure ? "https://" : "http://") + hostHdr + loc;
            HttpResult r2 = httpRequestEx(loc, method, timeoutSec, proxy, wantBody, verify, maxBody, redirects - 1);
            if (r2.ok) r2.ms += res.ms;
            return r2.ok ? r2 : res;
        }
    }
    if (wantBody) {
        std::string body = data.substr(hEnd + 4);
        long clen = -1;
        std::string cl = headerValue(head, "Content-Length");
        if (!cl.empty()) clen = atol(cl.c_str());
        while ((clen < 0 || (long)body.size() < clen) && body.size() < maxBody) {
            int n = st.rd(buf, sizeof(buf));
            if (n <= 0) break;
            body.append(buf, n);
        }
        std::string te = headerValue(head, "Transfer-Encoding");
        for (auto& c : te) c = (char)tolower((unsigned char)c);
        res.body = (te.find("chunked") != std::string::npos) ? dechunk(body) : body;
    }
    st.close();
    return res;
}
// Сигнатура как в Windows-версии: useProxy + строка прокси.
static HttpResult httpRequest(const std::string& url, const std::string& method,
                              int timeoutSec, bool useProxy, const std::string& proxyStr,
                              bool wantBody = false) {
    return httpRequestEx(url, method, timeoutSec, useProxy ? proxyStr : "", wantBody, false);
}
// Скачивание файла (с проверкой сертификата): сначала напрямую, при неудаче — через системный прокси.
static bool downloadFile(const std::string& url, const std::string& dest) {
    HttpResult r = httpRequestEx(url, "GET", 30, "", true, true, 256u << 20);
    if (!(r.ok && r.code == 200 && !r.body.empty())) {
        std::string px = getSystemProxy();
        if (!px.empty()) r = httpRequestEx(url, "GET", 30, px, true, true, 256u << 20);
    }
    if (!(r.ok && r.code == 200 && !r.body.empty())) return false;
    std::ofstream f(dest, std::ios::binary);
    if (!f) return false;
    f.write(r.body.data(), (std::streamsize)r.body.size());
    return (bool)f;
}

// ================== ОПРЕДЕЛЕНИЕ РЕЖИМА VPN ==================
enum class VpnMode { None, Proxy, Tun };
static VpnMode detectVpnMode(std::string& proxyOut) {
    proxyOut = getSystemProxy();
    if (!proxyOut.empty()) return VpnMode::Proxy;   // прокси-режим (v2rayN/Nekoray/Hiddify и т.п.)
    // TUN-режим = туннель владеет маршрутом по умолчанию. Просто поднятый tun
    // (например, Yggdrasil, который ведёт только свою сеть) не считается.
    if (defaultViaTunnel()) return VpnMode::Tun;
    return VpnMode::None;
}

struct GeoInfo { std::string ip, country, isp; };
static GeoInfo fetchGeo(bool useProxy, const std::string& proxy) {
    GeoInfo g;
    bool viaProxy = useProxy && !proxy.empty();
    HttpResult r = httpRequest("http://ip-api.com/json", "GET", 5, viaProxy, proxy, true);
    if (r.ok && !r.body.empty()) {
        std::smatch m;
        if (std::regex_search(r.body, m, std::regex("\"query\"\\s*:\\s*\"([^\"]+)\"")))   g.ip = m[1];
        if (std::regex_search(r.body, m, std::regex("\"country\"\\s*:\\s*\"([^\"]+)\""))) g.country = m[1];
        if (std::regex_search(r.body, m, std::regex("\"isp\"\\s*:\\s*\"([^\"]+)\"")))     g.isp = m[1];
    }
    if (g.ip.empty()) {
        HttpResult r2 = httpRequest("https://api.ipify.org", "GET", 4, viaProxy, proxy, true);
        if (r2.ok && !r2.body.empty()) g.ip = trim(r2.body);
    }
    return g;
}
static std::string fmtGeo(const GeoInfo& g) {
    if (g.ip.empty()) return "не удалось получить";
    std::string s = g.ip, extra;
    if (!g.country.empty()) extra = g.country;
    if (!g.isp.empty()) extra += (extra.empty() ? "" : ", ") + g.isp;
    return extra.empty() ? s : s + " (" + extra + ")";
}
// Внешний IP + страна через текущий путь (в прокси-режиме — через прокси).
static std::string getExternalGeo() {
    std::string proxy = getIEProxy();
    GeoInfo g = fetchGeo(true, proxy);
    if (g.ip.empty()) return "Unknown";
    return g.ip + (g.country.empty() ? "" : (" (" + g.country + ")"));
}

// ================== ПРОВЕРКА САЙТОВ (учёт режима VPN) ==================
static std::string fmtHttp(const HttpResult& r) {
    return (r.ok && r.code) ? (std::to_string(r.code) + " (" + std::to_string(r.ms) + "мс)")
                            : std::string("timeout");
}
// "Достижим" = сервер вообще ответил (любой HTTP-код, включая 403/405), а не timeout.
static bool httpReachable(const HttpResult& r) { return r.ok && r.code != 0; }

// ================== DNS (сырой UDP-запрос к указанному серверу) ==================
// Возвращает первый A-адрес или "" и заполняет rttMs.
static std::string dnsQueryA(const std::string& server, const std::string& name, int timeoutMs, long& rttMs) {
    rttMs = -1;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return "";
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(53);
    if (inet_pton(AF_INET, server.c_str(), &sa.sin_addr) != 1) { closesocket(s); return ""; }

    // Формируем пакет
    std::vector<uint8_t> pkt;
    uint16_t id = (uint16_t)(GetTickCount() & 0xFFFF);
    auto push16 = [&](uint16_t v){ pkt.push_back(v>>8); pkt.push_back(v&0xFF); };
    push16(id); push16(0x0100); push16(1); push16(0); push16(0); push16(0);
    // QNAME
    std::string label; std::istringstream iss(name); 
    std::string part;
    while (std::getline(iss, part, '.')) {
        pkt.push_back((uint8_t)part.size());
        for (char c : part) pkt.push_back((uint8_t)c);
    }
    pkt.push_back(0);
    push16(1); // QTYPE A
    push16(1); // QCLASS IN

    auto t0 = std::chrono::steady_clock::now();
    sendto(s, (const char*)pkt.data(), (int)pkt.size(), 0, (sockaddr*)&sa, sizeof(sa));

    fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
    timeval tv{ timeoutMs/1000, (timeoutMs%1000)*1000 };
    std::string result;
    if (select(s + 1, &rf, nullptr, nullptr, &tv) > 0) {
        uint8_t buf[512];
        int n = recvfrom(s, (char*)buf, sizeof(buf), 0, nullptr, nullptr);
        auto t1 = std::chrono::steady_clock::now();
        rttMs = (long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        if (n >= 12) {
            uint16_t qd = (buf[4]<<8)|buf[5];
            uint16_t an = (buf[6]<<8)|buf[7];
            size_t off = 12;
            // пропускаем вопросы
            for (int q = 0; q < qd; q++) {
                while (off < (size_t)n && buf[off] != 0) {
                    if ((buf[off] & 0xC0) == 0xC0) { off += 2; goto qdone; }
                    off += buf[off] + 1;
                }
                off += 1; qdone:; off += 4; // QTYPE+QCLASS
            }
            // ответы
            for (int a = 0; a < an && off + 12 <= (size_t)n; a++) {
                if ((buf[off] & 0xC0) == 0xC0) off += 2;
                else { while (off < (size_t)n && buf[off] != 0) off += buf[off]+1; off += 1; }
                if (off + 10 > (size_t)n) break;
                uint16_t type = (buf[off]<<8)|buf[off+1];
                uint16_t rdlen = (buf[off+8]<<8)|buf[off+9];
                off += 10;
                if (type == 1 && rdlen == 4 && off + 4 <= (size_t)n) {
                    char ipbuf[16];
                    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                             buf[off],buf[off+1],buf[off+2],buf[off+3]);
                    result = ipbuf; break;
                }
                off += rdlen;
            }
        }
    }
    closesocket(s);
    return result;
}


// ================== TCP CONNECT + БАННЕР (скан портов) ==================
static bool tcpConnect(const std::string& ip, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    connect(s, (sockaddr*)&sa, sizeof(sa));
    fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
    timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
    int r = select(s + 1, nullptr, &wf, nullptr, &tv);
    bool ok = false;
    if (r > 0) {
        int err = 0; socklen_t len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        ok = (err == 0);
    }
    closesocket(s);
    return ok;
}
static std::string grabBanner(const std::string& ip, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    connect(s, (sockaddr*)&sa, sizeof(sa));
    fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
    timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
    std::string banner;
    if (select(s + 1, nullptr, &wf, nullptr, &tv) > 0) {
        int err = 0; socklen_t len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        if (err == 0) {
            if (port==80 || port==8080) {
                std::string req = "HEAD / HTTP/1.0\r\n\r\n";
                send(s, req.c_str(), (int)req.size(), 0);
            }
            fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
            timeval tv2{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
            if (select(s + 1, &rf, nullptr, nullptr, &tv2) > 0) {
                char buf[1024];
                int n = recv(s, buf, sizeof(buf) - 1, 0);
                if (n > 0) { buf[n] = 0; banner = trim(std::string(buf, n)); }
            }
        }
    }
    closesocket(s);
    return banner;
}

// ================== БАЗА CVE (обновлена: сентябрь 2026) ==================
// Источники: openssh.org, httpd.apache.org, nginx (F5), postgresql.org,
// dev.mysql.com / Oracle CPU, NVD. Проверка по версии: сервис уязвим, если
// его версия >= introduced (или introduced пусто) И < fixedIn.
// Сопоставление по версии из баннера — эвристика: дистрибутивы часто
// бэкпортят фиксы, не меняя номер версии, поэтому возможны ложные срабатывания.
struct Vuln { std::string introduced; std::string fixedIn; std::string cve; std::string desc; };

// Сравнение версий: "1.28.3" vs "1.30.1". Возвращает -1/0/1. Буквы (9.9p1) игнорируются.
static int verCmp(const std::string& a, const std::string& b) {
    auto parse = [](const std::string& s) {
        std::vector<int> v; int cur = 0; bool has = false;
        for (char c : s) {
            if (c >= '0' && c <= '9') { cur = cur * 10 + (c - '0'); has = true; }
            else { if (has) { v.push_back(cur); cur = 0; has = false; } }
        }
        if (has) v.push_back(cur);
        return v;
    };
    std::vector<int> va = parse(a), vb = parse(b);
    size_t n = std::max(va.size(), vb.size());
    for (size_t i = 0; i < n; i++) {
        int x = i < va.size() ? va[i] : 0;
        int y = i < vb.size() ? vb[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

static std::map<std::string, std::vector<Vuln>> g_vulnDB = {
    {"OpenSSH", {
        {"6.8", "9.9.2", "CVE-2025-26465", "MitM при включённом VerifyHostKeyDNS: атакующий на пути может выдать себя за сервер (клиент)"},
        {"9.5", "9.9.2", "CVE-2025-26466", "Пре-аутентификационный DoS (память/CPU) через пакеты SSH2_MSG_PING (клиент и сервер)"},
        {"7.4", "10.0",  "CVE-2025-32728", "DisableForwarding не отключает X11 и forwarding агента вопреки документации"},
        {"",    "10.3",  "CVE-2026-35386", "Выполнение команд через shell-метасимволы в имени пользователя в командной строке"},
        {"",    "10.3",  "CVE-2026-35414", "Некорректная обработка principals в authorized_keys (CVSS 8.1)"},
    }},
    {"Apache", {
        {"2.4.0",  "2.4.68", "CVE-2026-44631", "Heap underflow в ap_regname через crafted regex в конфигурации"},
        {"2.4.66", "2.4.67", "CVE-2026-23918", "Double-free в HTTP/2 при early reset — возможен RCE (CVSS 8.8)"},
        {"2.4.0",  "2.4.67", "CVE-2026-28780", "Heap buffer overflow в mod_proxy_ajp (CVSS 8.1)"},
        {"2.4.0",  "2.4.67", "CVE-2026-24072", "Эскалация привилегий через .htaccess (mod_rewrite/ap_expr)"},
        {"2.4.0",  "2.4.66", "CVE-2025-59775", "SSRF на Windows (AllowEncodedSlashes On) — утечка NTLM-хэшей"},
    }},
    {"nginx", {
        {"",       "1.30.1", "CVE-2026-42945", "NGINX Rift: heap overflow в ngx_http_rewrite_module — краш воркера/RCE"},
        {"",       "1.28.3", "CVE-2026-32647", "Переполнение буфера в ngx_http_mp4_module — возможен RCE (crafted MP4)"},
        {"",       "1.28.3", "CVE-2026-27654", "Heap overflow в ngx_http_dav_module — path traversal через COPY/MOVE"},
        {"1.31.0", "1.31.2", "CVE-2026-42530", "Use-after-free в ngx_http_v3_module (HTTP/3, CVSS 8.1)"},
        {"1.31.0", "1.31.2", "CVE-2026-42055", "Heap overflow в ngx_http_proxy_v2_module/grpc (CVSS 8.1)"},
        {"",       "1.27.4", "CVE-2025-23419", "Обход client-cert auth через возобновление TLS-сессий"},
    }},
    {"MySQL", {
        {"8.4.0", "8.4.10", "CVE-2026-46863", "Неаутентифицированный DoS через обработку соединений (MySQL Protocol)"},
        {"9.0.0", "9.7.1",  "CVE-2026-46863", "Неаутентифицированный DoS через обработку соединений (MySQL Protocol)"},
        {"8.0.0", "8.0.43", "CVE-2025-50102", "DoS через компонент Server: Optimizer"},
        {"8.4.0", "8.4.6",  "CVE-2025-50102", "DoS через компонент Server: Optimizer"},
    }},
    {"PostgreSQL", {
        {"13.0", "13.22", "CVE-2025-8714", "RCE в psql/сервере при восстановлении через pg_dump (CVSS 8.8)"},
        {"14.0", "14.19", "CVE-2025-8714", "RCE в psql/сервере при восстановлении через pg_dump (CVSS 8.8)"},
        {"15.0", "15.14", "CVE-2025-8714", "RCE в psql/сервере при восстановлении через pg_dump (CVSS 8.8)"},
        {"16.0", "16.10", "CVE-2025-8714", "RCE в psql/сервере при восстановлении через pg_dump (CVSS 8.8)"},
        {"17.0", "17.6",  "CVE-2025-8714", "RCE в psql/сервере при восстановлении через pg_dump (CVSS 8.8)"},
        {"14.0", "14.24", "CVE-2026-14664", "Heap overflow в regexp — выполнение произвольного кода (CVSS 8.8)"},
        {"15.0", "15.19", "CVE-2026-14664", "Heap overflow в regexp — выполнение произвольного кода (CVSS 8.8)"},
        {"16.0", "16.15", "CVE-2026-14664", "Heap overflow в regexp — выполнение произвольного кода (CVSS 8.8)"},
        {"17.0", "17.11", "CVE-2026-14664", "Heap overflow в regexp — выполнение произвольного кода (CVSS 8.8)"},
        {"18.0", "18.6",  "CVE-2026-14664", "Heap overflow в regexp — выполнение произвольного кода (CVSS 8.8)"},
    }},
    {"ProFTPD", {
        {"", "1.3.9",  "CVE-2024-57392", "Переполнение буфера — RCE или DoS через crafted-сообщение"},
        {"", "1.3.9",  "CVE-2026-42167", "RCE в mod_sql через имя пользователя (%U логирование + SQL COPY TO PROGRAM)"},
        {"", "1.3.9",  "CVE-2026-44331", "SQL-инъекция в mod_wrap2_sql через reverse-DNS имя (CVSS 8.1)"},
        {"", "1.3.10", "CVE-2026-35025", "Обход Directory ACL через /proc/self/root в RNFR (CVSS 8.1)"},
        {"", "1.3.10", "CVE-2026-63090", "Heap overflow в mod_sftp — RCE (аутентиф. пользователь)"},
    }},
    {"vsftpd", {
        {"", "3.0.6", "CVE-2025-14242", "Integer overflow при парсинге параметра ls — DoS"},
    }},
};

static std::vector<Vuln> testVulns(const std::string& service, const std::string& version) {
    std::vector<Vuln> found;
    if (version.empty()) return found;
    auto it = g_vulnDB.find(service);
    if (it == g_vulnDB.end()) return found;
    for (auto& e : it->second) {
        bool okLow  = e.introduced.empty() || verCmp(version, e.introduced) >= 0;
        bool okHigh = e.fixedIn.empty()    || verCmp(version, e.fixedIn)     <  0;
        if (okLow && okHigh) found.push_back(e);
    }
    return found;
}

static std::map<int,std::string> g_wellKnown = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},{80,"HTTP"},
    {110,"POP3"},{111,"RPC"},{135,"RPC"},{139,"NetBIOS"},{143,"IMAP"},{443,"HTTPS"},
    {445,"SMB"},{993,"IMAPS"},{995,"POP3S"},{1723,"PPTP"},{3306,"MySQL"},{3389,"RDP"},
    {5432,"PostgreSQL"},{5900,"VNC"},{6379,"Redis"},{8080,"HTTP-Alt"},{8443,"HTTPS-Alt"},
    {27017,"MongoDB"},
};

// ================== СПИСОК ПОРТОВ (Settings\ports.txt) ==================
// Порты по умолчанию — те, что раньше были зашиты в код скана.
static const int DEFAULT_PORTS[] = {21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5432,5900,6379,8080,8443,27017};
static const int MAX_RANGE_PORTS = 1000;   // диапазон не длиннее, чтобы скан не шёл часами
static std::string portName(int p) {       // название сервиса (без вставки в map — безопасно из разных потоков)
    auto it = g_wellKnown.find(p);
    return it == g_wellKnown.end() ? std::string() : it->second;
}
// "80" или "8000-8010" → a, b. Возвращает текст ошибки или "" если всё верно.
static std::string parsePortSpec(const std::string& raw, int& a, int& b) {
    std::string s = trim(raw);
    if (s.empty()) return "пусто";
    size_t dash = s.find('-');
    auto num = [](const std::string& t, int& out) -> bool {
        if (t.empty() || t.size() > 5) return false;
        for (char c : t) if (c < '0' || c > '9') return false;
        out = std::stoi(t); return true;
    };
    if (dash == std::string::npos) {
        if (!num(s, a)) return "нужно число или диапазон «от-до»";
        b = a;
    } else {
        if (!num(trim(s.substr(0, dash)), a) || !num(trim(s.substr(dash + 1)), b))
            return "диапазон пишется так: 8000-8010";
        if (a > b) return "начало диапазона больше конца";
    }
    if (a < 1 || b > 65535) return "порт должен быть от 1 до 65535";
    if (b - a + 1 > MAX_RANGE_PORTS) return "диапазон больше " + std::to_string(MAX_RANGE_PORTS) + " портов";
    return "";
}
static void writeDefaultPorts(const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    o << "# Порты для сканирования\r\n# Формат: порт или диапазон от-до;комментарий\r\n";
    for (int p : DEFAULT_PORTS) o << p << ";" << portName(p) << "\r\n";
}
// Порты для скана: из ports.txt (диапазоны разворачиваются, повторы убираются).
static std::vector<int> loadPorts() {
    std::string path = g_settingsDir + "/ports.txt";
    if (!pathExists(path)) writeDefaultPorts(path);
    std::vector<int> out;
    std::vector<bool> seen(65536, false);
    std::ifstream f(path, std::ios::binary);
    std::string line;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.size() >= 3 && (unsigned char)t[0] == 0xEF) t = t.substr(3);   // BOM
        if (t.empty() || t[0] == '#') continue;
        size_t sc = t.find(';');
        int a = 0, b = 0;
        if (!parsePortSpec(sc == std::string::npos ? t : t.substr(0, sc), a, b).empty()) continue;
        for (int p = a; p <= b; p++) if (!seen[p]) { seen[p] = true; out.push_back(p); }
    }
    if (out.empty()) out.assign(std::begin(DEFAULT_PORTS), std::end(DEFAULT_PORTS));
    return out;
}

struct PortResult { int port; bool open; std::string service, version, os, banner; };
static PortResult parseBanner(const std::string& ip, int port, int timeoutMs) {
    PortResult pr{ port, true, "", "", "", "" };
    std::string b = grabBanner(ip, port, timeoutMs);
    pr.banner = b;
    auto sk = g_wellKnown.find(port);
    if (sk != g_wellKnown.end()) pr.service = sk->second;
    if (!b.empty()) {
        std::smatch m;
        if (std::regex_search(b, m, std::regex("(Apache|nginx|Microsoft-IIS|lighttpd)[/ ]?([\\d\\.]+)"))) {
            pr.service = m[1]; pr.version = m[2];
            if (b.find("(Ubuntu)")!=std::string::npos) pr.os="Ubuntu";
            else if (b.find("(Debian)")!=std::string::npos) pr.os="Debian";
            else if (b.find("(CentOS)")!=std::string::npos) pr.os="CentOS";
            else if (b.find("Win")!=std::string::npos) pr.os="Windows";
        } else if (std::regex_search(b, m, std::regex("OpenSSH[_ ]?([\\d\\.]+)"))) {
            pr.service="OpenSSH"; pr.version=m[1];
            if (b.find("Ubuntu")!=std::string::npos) pr.os="Ubuntu";
            else if (b.find("Debian")!=std::string::npos) pr.os="Debian";
        } else if (std::regex_search(b, m, std::regex("ProFTPD ([\\d\\.]+)"))) {
            pr.service="ProFTPD"; pr.version=m[1];
        } else if (b.find("MySQL")!=std::string::npos) {
            pr.service="MySQL";
            if (std::regex_search(b, m, std::regex("([\\d\\.]+)-"))) pr.version=m[1];
        } else if (b.find("PostgreSQL")!=std::string::npos) {
            pr.service="PostgreSQL";
            if (std::regex_search(b, m, std::regex("([\\d\\.]+)"))) pr.version=m[1];
        } else if (b.find("ESMTP")!=std::string::npos) {
            pr.service="ESMTP";
        }
    }
    return pr;
}

static bool invokeServiceScan(const std::string& logFile, const std::vector<Item>& targets) {
    std::vector<int> ports = loadPorts();   // из Settings\ports.txt
    int timeoutMs = g_config.ConnectionTimeout;
    int bannerMs  = g_config.BannerTimeout;

    writeLog("\n--- СКАНИРОВАНИЕ СЕРВИСОВ (по баннерам) ---", "Green", logFile);
    if (targets.empty()) { writeLog(" Нет целей для сканирования.", "Red", logFile); return false; }
    writeLog("Целей: " + std::to_string(targets.size()) + ", портов: " +
             std::to_string(ports.size()) + ", таймаут: " +
             std::to_string(timeoutMs) + " мс", "Cyan", logFile);

    for (auto& t : targets) {
        std::string ip = t.Value;
        if (ip.empty()) continue;
        std::string disp = t.Comment.empty() ? ip : (ip + " (" + t.Comment + ")");
        writeLog("\n Сканирование " + disp, "Magenta", logFile);

        std::vector<PortResult> results;
        for (int p : ports) {
            if (tcpConnect(ip, p, timeoutMs)) results.push_back(parseBanner(ip, p, bannerMs));
            else results.push_back({p,false,"","","",""});
        }
        std::string osDet;
        for (auto& r : results) if (r.open && !r.os.empty()) { osDet = r.os; break; }
        if (!osDet.empty()) writeLog("   Операционная система: " + osDet, "Cyan", logFile);
        int openCount = 0; for (auto& r : results) if (r.open) openCount++;
        writeLog("   Открыто портов: " + std::to_string(openCount), "Green", logFile);

        std::vector<PortResult> openPorts;
        for (auto& r : results) {
            if (r.open) {
                std::string svc = r.service.empty() ? portName(r.port) : r.service;
                writeLog("  " + std::to_string(r.port) + "/tcp - " + svc + " - ОТКРЫТ", "Green", logFile);
                openPorts.push_back(r);
            } else {
                writeLog("  " + std::to_string(r.port) + "/tcp - ЗАКРЫТ", "Red", logFile);
            }
        }
        bool anyVuln = false;
        for (auto& r : openPorts) {
            if (r.version.empty()) continue;
            auto vs = testVulns(r.service, r.version);
            if (!vs.empty()) {
                if (!anyVuln) { writeLog("\n   --- НАЙДЕННЫЕ УЯЗВИМОСТИ ---", "Red", logFile); anyVuln = true; }
                writeLog("   " + r.service + " v" + r.version + " (порт " + std::to_string(r.port) + "):", "Yellow", logFile);
                for (auto& v : vs)
                    writeLog("     - " + v.cve + ": " + v.desc, "Gray", logFile);
            }
        }
        if (!anyVuln) writeLog("\n    Уязвимостей не найдено.", "Green", logFile);
    }
    return true;
}

// ================== ПОЛНАЯ ДИАГНОСТИКА: HTTP + все DNS ==================
static bool invokeWebAndDns(const std::string& logFile, const std::vector<Item>& sitesOverride = {}) {
    std::vector<Item> sites = sitesOverride.empty() ? loadItemList("sites.txt") : sitesOverride;
    if (sites.empty()) { writeLog("Нет сайтов для диагностики. Заполните sites.txt.", "Red", logFile); return false; }
    auto dnsTargets = loadItemList("dns_targets.txt");

    writeLog("\n--- ПОЛНАЯ ДИАГНОСТИКА (HTTP + все DNS) ---", "Green", logFile);
    std::string proxy;
    VpnMode mode = detectVpnMode(proxy);

    struct DnsSrv { std::string host, comment; };
    std::vector<DnsSrv> servers;
    std::string sysDns = getSystemDns();
    if (!sysDns.empty()) { servers.push_back({sysDns, "Системный DNS"}); 
        writeLog("Системный DNS: " + sysDns, "Cyan", logFile); }
    for (auto& d : dnsTargets) servers.push_back({d.Value, d.Comment});
    if (servers.empty()) { writeLog("Нет DNS-серверов для проверки.", "Red", logFile); return false; }

    int timeout = (g_config.HttpTimeout > 0) ? g_config.HttpTimeout : 5;

    // Заголовки: Сайт | Напрямую | Через VPN | <каждый DNS>
    std::vector<std::string> headers = { "Сайт", "Напрямую", "Через VPN" };
    std::vector<size_t> minW = { 4, 13, 13 };
    for (auto& it : sites) minW[0] = std::max(minW[0], dispLen(it.Value));
    for (auto& srv : servers) { headers.push_back(srv.host + " [" + srv.comment + "]"); minW.push_back(24); }

    writeLog("(заблокированные напрямую ждут таймаут " + std::to_string(timeout) + "с — это нормально)", "Gray", logFile);
    auto w = tableWidths(headers, minW);
    tableHead(headers, w, logFile);

    int anyMismatchTotal = 0;
    for (auto& it : sites) {
        std::string dom = it.Value;
        HttpResult direct = httpRequest(dom, "GET", timeout, false, "");
        HttpResult viaVpn = proxy.empty() ? direct : httpRequest(dom, "GET", timeout, true, proxy);
        bool rd = httpReachable(direct), rv = httpReachable(viaVpn);

        std::vector<std::string> row = { dom, fmtHttp(direct), fmtHttp(viaVpn) };

        std::string refIp; bool mismatch = false;
        std::vector<std::string> dnsCells;
        for (auto& srv : servers) {
            long rtt = -1;
            std::string ip = dnsQueryA(srv.host, dom, timeout*1000, rtt);
            if (!ip.empty()) { if (refIp.empty()) refIp = ip; else if (ip != refIp) mismatch = true; }
            dnsCells.push_back(ip.empty() ? "нет ответа" : (ip + " (" + std::to_string(rtt) + "мс)"));
        }
        for (size_t i = 0; i < servers.size(); i++) {
            std::string ipOnly = dnsCells[i].substr(0, dnsCells[i].find(' '));
            if (!refIp.empty() && ipOnly != "нет" && ipOnly != refIp) dnsCells[i] += " !!!";
            row.push_back(dnsCells[i]);
        }
        if (mismatch) anyMismatchTotal++;
        std::string col;
        if (mode == VpnMode::Proxy) {
            // Прокси-режим: есть два разных пути — сравниваем «напрямую» и «через VPN».
            col = (!rd && !rv) ? "Red"           // недоступен даже через VPN
                : (mismatch    ? "Yellow"        // DNS разошлись (подмена/CDN)
                : ((!rd && rv) ? "Green"         // VPN починил блок
                : "White"));                     // работает и напрямую
        } else {
            // TUN / нет прокси: путь один (туннель или прямой). Красим по доступности.
            col = !rd         ? "Red"            // недоступен
                : (mismatch   ? "Yellow"         // DNS отдают разные IP (!!!)
                : "Green");                      // доступен
        }
        tableRow(row, w, col, logFile);
    }
    tableSep(w, logFile);
    writeLog("", "White", logFile);
    if (mode == VpnMode::Proxy)
        writeLog("Красный — недоступен даже через VPN. Жёлтый — DNS отдают разные IP (!!!). Зелёный — открывается только через VPN. Белый — работает и напрямую.", "Gray", logFile);
    else
        writeLog("Красный — недоступен. Жёлтый — DNS отдают разные IP (!!!). Зелёный — доступен (через текущий путь/туннель). Колонки «Напрямую»/«Через VPN» в режиме туннеля совпадают — путь один.", "Gray", logFile);
    writeLog("Сайтов: " + std::to_string(sites.size()) + ", с расхождением DNS: " + std::to_string(anyMismatchTotal), "Cyan", logFile);
    return true;
}


// ================== ВНЕШНИЙ IP + СТАРТОВЫЙ ЗАГОЛОВОК ==================
static std::string getExternalIp() {
    std::string proxy = getIEProxy();
    // через прокси (покажет IP выхода VPN), иначе напрямую
    HttpResult r = httpRequest("https://api.ipify.org", "GET", 4, !proxy.empty(), proxy, true);
    if (r.ok && !r.body.empty()) return trim(r.body);
    r = httpRequest("https://ifconfig.me/ip", "GET", 4, false, "", true);
    if (r.ok && !r.body.empty()) return trim(r.body);
    return "Unknown";
}
static std::string startReport(const std::string& folderKey) {
    std::string logFile = getLogFilePath(folderKey);
    SYSTEMTIME st; GetLocalTime(&st);
    char ts[64];
    snprintf(ts, sizeof(ts), "%02d.%02d.%04d %02d:%02d:%02d",
             st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
    std::string ip = getExternalIp();
    writeLog("", "Cyan", logFile);
    writeLog("================ ОТЧЁТ О СОСТОЯНИИ СЕТИ ================", "Cyan", logFile);
    writeLog("Дата и время: " + std::string(ts), "Yellow", logFile);
    writeLog("IP проверяющего: " + ip, "Yellow", logFile);
    writeLog("Лог-файл: " + toU8(logFile), "Yellow", logFile);
    writeLog("========================================================", "Cyan", logFile);
    return logFile;
}

static void writeStateJson(const std::string& txtLogFile) {
    if (txtLogFile.empty()) return;
    std::string jpath = txtLogFile;                 // .txt -> .json рядом
    size_t dot = jpath.rfind('.');
    if (dot != std::string::npos) jpath = jpath.substr(0, dot);
    jpath += ".json";

    std::string proxyW;
    VpnMode mode = detectVpnMode(proxyW);
    const char* modeStr = (mode == VpnMode::Proxy) ? "proxy" : (mode == VpnMode::Tun) ? "tun" : "none";

    SYSTEMTIME st; GetLocalTime(&st);
    char ts[48];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    GeoInfo direct = fetchGeo(false, "");
    GeoInfo viaVpn = (mode == VpnMode::Proxy) ? fetchGeo(true, proxyW) : GeoInfo{};

    auto geoObj = [&](const GeoInfo& g) -> std::string {
        if (g.ip.empty()) return "null";
        return "{ \"ip\": " + jStr(g.ip) + ", \"country\": " + jStr(g.country) +
               ", \"isp\": " + jStr(g.isp) + " }";
    };

    std::ostringstream j;
    j << "{\n";
    j << "  \"tool\": \"Lag\",\n";
    j << "  \"version\": \"" << SCRIPT_VERSION << "\",\n";
    j << "  \"timestamp\": " << jStr(ts) << ",\n";
    j << "  \"vpn_mode\": \"" << modeStr << "\",\n";

    if (mode == VpnMode::Proxy) {
        std::string ph; int pp = 0;
        parseProxyAddr(proxyW, ph, pp);
        int to = std::max(g_config.HttpTimeout, 1) * 1000;
        ProbeResult h  = (pp > 0)    ? probeHttpProxy(ph, pp, to) : ProbeResult{};
        int sPort = g_config.SocksPort > 0 ? g_config.SocksPort : pp - 1;
        ProbeResult sk = (sPort > 0) ? probeSocks5(ph, sPort, to) : ProbeResult{};
        j << "  \"proxy\": { \"server\": " << jStr(toU8(proxyW))
          << ", \"http_ok\": " << (h.tunnelOk ? "true" : "false")
          << ", \"socks_ok\": " << (sk.tunnelOk ? "true" : "false") << " },\n";
    } else {
        j << "  \"proxy\": null,\n";
    }

    j << "  \"external_ip\": { \"direct\": " << geoObj(direct)
      << ", \"via_vpn\": " << geoObj(viaVpn) << " },\n";

    j << "  \"adapters\": [";
    { bool first = true;
      for (auto& a : listAdapters()) {
          if (a.type == "Loopback") continue;
          j << (first ? "\n" : ",\n") << "    { \"name\": " << jStr(a.name)
            << ", \"type\": " << jStr(a.type) << ", \"ipv4\": " << jStr(a.ipv4)
            << ", \"gateway\": " << (a.hasGw ? "true" : "false")
            << ", \"tunnel\": " << (a.vpnLike ? "true" : "false") << " }";
          first = false;
      }
      j << (first ? "" : "\n  ") << "],\n";
    }

    j << "  \"dns_servers\": [";
    { bool first = true;
      for (auto& d : listDnsServers()) {
          j << (first ? "\n" : ",\n") << "    { \"ip\": " << jStr(d.ip)
            << ", \"adapter\": " << jStr(d.adapter) << " }";
          first = false;
      }
      j << (first ? "" : "\n  ") << "],\n";
    }

    j << "  \"bypass_routes\": [";
    { bool first = true;
      for (auto& ip : listBypassRoutes()) { j << (first ? "" : ", ") << jStr(ip); first = false; }
      j << "]\n";
    }
    j << "}\n";

    std::ofstream f(jpath, std::ios::binary);
    if (f) f << j.str();
}

static bool invokeNetState(const std::string& logFile) {
    writeLog("\n============== СОСТОЯНИЕ СЕТИ / VPN ==============", "Green", logFile);
    std::string proxy;
    VpnMode mode = detectVpnMode(proxy);
    ConnInfo ci = getConnectionType();

    std::string modeStr = (mode == VpnMode::Proxy) ? "прокси (" + toU8(proxy) + ")"
                        : (mode == VpnMode::Tun)   ? "туннель (TUN) — маршрут по умолчанию через VPN"
                        : "не обнаружен";
    writeLog("Режим VPN:         " + modeStr, mode == VpnMode::None ? "Yellow" : "Cyan", logFile);
    std::string conn = ci.BaseType;
    if (!ci.Detail.empty() && ci.Detail != "-") conn += " (" + ci.Detail + ")";
    if (!ci.LinkSpeed.empty()) conn += ", " + ci.LinkSpeed;
    if (ci.VpnActive) conn += "; поднят туннельный адаптер: " + ci.VpnName;
    writeLog("Подключение:       " + conn, "Cyan", logFile);

    // --- Внешний IP ---
    writeLog("\n--- Внешний IP ---", "Green", logFile);
    if (mode == VpnMode::Proxy) {
        GeoInfo real = fetchGeo(false, "");
        GeoInfo exitg = fetchGeo(true, proxy);
        writeLog("Реальный IP (напрямую):   " + fmtGeo(real), "White", logFile);
        writeLog("Внешний IP (через VPN):   " + fmtGeo(exitg), "White", logFile);
        if (exitg.ip.empty())
            writeLog("  -> через прокси IP получить не удалось: прокси не пропускает трафик   [ПРОБЛЕМА]", "Red", logFile);
        else if (!real.ip.empty() && real.ip == exitg.ip)
            writeLog("  -> IP совпадают: прокси не меняет внешний IP   [ПРОБЛЕМА]", "Red", logFile);
        else
            writeLog("  -> IP различаются: трафик через прокси выходит с VPN-сервера   [OK]", "Green", logFile);
    } else if (mode == VpnMode::Tun) {
        GeoInfo g = fetchGeo(false, "");
        writeLog("Внешний IP (через туннель): " + fmtGeo(g), "White", logFile);
        writeLog("  -> в TUN-режиме весь трафик идёт через туннель: страна должна быть страной VPN-сервера", "Gray", logFile);
    } else {
        GeoInfo g = fetchGeo(false, "");
        writeLog("Внешний IP: " + fmtGeo(g), "White", logFile);
        writeLog("  -> VPN не найден: это твой реальный IP", "Yellow", logFile);
    }

    // --- Локальный прокси-клиент ---
    writeLog("\n--- Локальный прокси-клиент ---", "Green", logFile);
    std::string pHost; int pPort = 0;
    if (proxy.empty() || !parseProxyAddr(proxy, pHost, pPort)) {
        writeLog("Системный прокси не задан — проверка портов пропущена.", "Gray", logFile);
    } else {
        int to = std::max(g_config.HttpTimeout, 1) * 1000;
        ProbeResult h = probeHttpProxy(pHost, pPort, to);
        printProbe("HTTP", pHost + ":" + std::to_string(pPort), h, true, logFile);
        int sPort = g_config.SocksPort > 0 ? g_config.SocksPort : pPort - 1;
        ProbeResult s = probeSocks5(pHost, sPort, to);
        printProbe("SOCKS", pHost + ":" + std::to_string(sPort), s, false, logFile);
        if (g_config.SocksPort <= 0)
            writeLog("  (SOCKS-порт взят автоматически: HTTP-порт - 1, как в v2rayN)", "Gray", logFile);
    }

    // --- Активные интерфейсы ---
    writeLog("\n--- Активные интерфейсы ---", "Green", logFile);
    {
        std::vector<std::string> headers = { "Интерфейс", "Тип", "IPv4", "Шлюз", "Туннель" };
        auto adapters = listAdapters();
        std::vector<size_t> minW = { 9, 8, 7, 4, 7 };
        for (auto& a : adapters) {
            if (a.type == "Loopback") continue;
            minW[0] = std::max(minW[0], dispLen(a.name));
            minW[1] = std::max(minW[1], dispLen(a.type));
            minW[2] = std::max(minW[2], dispLen(a.ipv4));
        }
        auto w = tableWidths(headers, minW);
        tableHead(headers, w, logFile);
        for (auto& a : adapters) {
            if (a.type == "Loopback") continue;
            tableRow({ a.name, a.type, a.ipv4.empty() ? "-" : a.ipv4,
                       a.hasGw ? "есть" : "-", a.vpnLike ? "да" : "-" },
                     w, a.vpnLike ? "Cyan" : "White", logFile);
        }
        tableSep(w, logFile);
    }

    // --- Выходной интерфейс до целей ---
    writeLog("\n--- Через какой интерфейс уходит трафик (маршрут ОС) ---", "Green", logFile);
    // Цели берутся с этого компьютера и из твоих списков, а не вшиты в код:
    //  - обходные маршруты VPN-клиента (в TUN-режиме это адрес VPN-сервера);
    //  - DNS-серверы, прописанные на адаптерах (куда Windows реально шлёт DNS-запросы);
    //  - маршрут по умолчанию в интернет;
    //  - первые сайты из sites.txt.
    enum class TKind { Server, Dns, Inet, Site };
    struct Target { std::string host, label; TKind kind; };
    std::vector<Target> targets;
    if (mode == VpnMode::Tun) {
        auto by = listBypassRoutes();
        for (size_t i = 0; i < by.size() && i < 5; i++)
            targets.push_back({ by[i], "VPN-сервер, обход туннеля", TKind::Server });
    }
    for (auto& d : listDnsServers())
        targets.push_back({ d.ip, "DNS: " + d.adapter, TKind::Dns });
    targets.push_back({ "1.1.1.1", "интернет", TKind::Inet });
    {
        auto sites = loadItemList("sites.txt");
        for (size_t i = 0; i < sites.size() && i < 3; i++)
            targets.push_back({ sites[i].Value, sites[i].Comment.empty() ? "сайт" : sites[i].Comment, TKind::Site });
    }

    std::vector<std::string> headers = { "Цель", "IP", "Интерфейс", "Лок. адрес", "Маршрут" };
    std::vector<size_t> minW = { 4, 15, 9, 13, 7 };
    std::vector<RouteInfo> routes;
    for (auto& t : targets) {
        RouteInfo r = routeTo(t.host);
        routes.push_back(r);
        minW[0] = std::max(minW[0], dispLen(t.host + " (" + t.label + ")"));
        minW[2] = std::max(minW[2], dispLen(r.ifName));
    }
    auto w = tableWidths(headers, minW);
    tableHead(headers, w, logFile);
    int leaks = 0, dnsOut = 0;
    for (size_t i = 0; i < targets.size(); i++) {
        const RouteInfo& r = routes[i];
        std::string name = targets[i].host + " (" + targets[i].label + ")";
        if (!r.ok) {
            tableRow({ name, r.ip.empty() ? "-" : r.ip, r.err, "-", "-" }, w, "Yellow", logFile);
            continue;
        }
        std::string route = r.viaTunnel ? "туннель" : "физ.";
        std::string color = "White";
        if (mode == VpnMode::Tun && !r.viaTunnel) {
            if (targets[i].kind == TKind::Server) {
                color = "Gray";                                   // так и должно быть
            } else if (targets[i].kind == TKind::Dns) {
                route += "  мимо VPN"; color = "Yellow"; dnsOut++;
            } else {
                route += "  УТЕЧКА"; color = "Red"; leaks++;
            }
        }
        tableRow({ name, r.ip, r.ifName, r.localIp, route }, w, color, logFile);
    }
    tableSep(w, logFile);

    if (mode == VpnMode::Tun) {
        if (leaks > 0)
            writeLog("Утечка маршрута: " + std::to_string(leaks) +
                     " цел(и) идут мимо туннеля через физический интерфейс!", "Red", logFile);
        else
            writeLog("Утечек маршрута нет: весь трафик (кроме самого VPN-сервера) идёт через туннель.", "Green", logFile);
        if (dnsOut > 0)
            writeLog("DNS-сервер адаптера доступен мимо туннеля. Если VPN-клиент не перехватывает DNS "
                     "(в настройках: hijack DNS / FakeIP), запросы к сайтам видит провайдер.", "Yellow", logFile);
    } else if (mode == VpnMode::Proxy) {
        writeLog("Прокси-режим: на уровне маршрутов ОС всё идёт через физический интерфейс — это нормально.", "Gray", logFile);
        writeLog("Прокси работает на уровне приложений; утечку маршрута эта таблица ловит только в TUN-режиме.", "Gray", logFile);
    }

    writeStateJson(logFile);   // машиночитаемый снимок рядом с .txt
    writeLog("\nМашиночитаемый снимок состояния сохранён рядом: " +
             toU8(logFile).substr(0, toU8(logFile).rfind('.')) + ".json", "Gray", logFile);
    return true;
}

// ================== ЗАПУСК ВНЕШНИХ ПРОГРАММ ==================
static std::string stripAnsi(const std::string& s) {
    static const std::regex re("\x1b\\[[0-9;?]*[A-Za-z]");
    return std::regex_replace(s, re, "");
}
// Запуск с перехватом вывода: каждая строка — на экран и в лог (без ANSI-цветов).
static int runAndTee(const std::string& cmdline, const std::string& logFile, const std::string& color = "White") {
    FILE* p = popen((cmdline + " </dev/null 2>&1").c_str(), "r");
    if (!p) { writeLog("Не удалось запустить: " + cmdline, "Red", logFile); return -1; }
    std::string line; int c;
    while ((c = fgetc(p)) != EOF) {
        if (c == '\r') continue;
        if (c == '\n') { writeLog(stripAnsi(line), color, logFile); line.clear(); }
        else line += (char)c;
    }
    if (!line.empty()) writeLog(stripAnsi(line), color, logFile);
    int st = pclose(p);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// ================== NEXTTRACE ==================
static bool isAdmin() { return geteuid() == 0; }
// У файла есть capabilities (setcap cap_net_raw) — тогда трассировка работает и без root.
static bool hasFileCaps(const std::string& path) {
    return getxattr(path.c_str(), "security.capability", nullptr, 0) > 0;
}
static std::string nexttraceArch() {
    utsname u{}; uname(&u);
    std::string m = u.machine;
    if (m == "x86_64" || m == "amd64") return "amd64";
    if (m == "aarch64" || m == "arm64") return "arm64";
    if (m.rfind("armv7", 0) == 0) return "armv7";
    if (m == "i386" || m == "i686") return "386";
    if (m == "riscv64") return "riscv64";
    return m;
}
static std::string ensureNextTrace() {
    std::string local = g_toolsDir + "/nexttrace";
    if (access(local.c_str(), X_OK) == 0) return local;
    std::string sys = trim(runCmd("command -v nexttrace 2>/dev/null"));
    if (!sys.empty()) return sys;
    writeLog("NextTrace не найден. Скачиваю Linux-сборку (" + nexttraceArch() + ")...", "Yellow");
    std::string url = "https://github.com/nxtrace/NTrace-core/releases/latest/download/nexttrace_linux_" + nexttraceArch();
    ensureDirRec(g_toolsDir);
    if (!downloadFile(url, local)) {
        writeLog("Не удалось скачать NextTrace. Поставь его сам (https://github.com/nxtrace/NTrace-core) "
                 "или положи бинарник в " + local, "Red");
        return "";
    }
    chmod(local.c_str(), 0755);
    writeLog("NextTrace сохранён: " + local, "Green");
    return local;
}
static bool analyzeTrace(const Item& target, const std::string& logFile) {
    if (target.Value.empty()) { writeLog("Ошибка: пустая цель трассировки.", "Red", logFile); return false; }
    std::string disp = target.Comment.empty() ? target.Value : (target.Value + " (" + target.Comment + ")");
    writeLog("\n--- ТРАССИРОВКА TCP ДО " + disp + " ---", "Cyan", logFile);

    if (g_nexttracePath.empty()) g_nexttracePath = ensureNextTrace();
    if (g_nexttracePath.empty()) { writeLog("NextTrace недоступен.", "Red", logFile); return false; }
    if (!isAdmin() && !hasFileCaps(g_nexttracePath)) {
        writeLog("Для TCP-трассировки нужны «сырые» сокеты: запусти Lag через sudo или один раз выдай права NextTrace:", "Yellow", logFile);
        writeLog("  sudo setcap cap_net_raw,cap_net_admin+eip " + g_nexttracePath, "White", logFile);
        return false;
    }
    bool ipv6 = target.Value.find(':') != std::string::npos;
    int hops = (g_config.MaxHops >= 1 && g_config.MaxHops <= 64) ? g_config.MaxHops : 30;
    std::string cmd = shellQuote(g_nexttracePath) + " --tcp --port 443 --language en --max-hops " +
                      std::to_string(hops) + (ipv6 ? " --ipv6 " : " --ipv4 ") + shellQuote(target.Value);
    runAndTee(cmd, logFile);
    return true;
}

// ================== ОБНОВЛЕНИЕ ==================
static std::string extractVersion(const std::string& content) {
    std::smatch m;
    if (std::regex_search(content, m, std::regex("VERSION\\s*=\\s*([\\d\\.]+)"))) return m[1];
    return "";
}
static std::string fetchRemoteVersion() {
    HttpResult r = httpRequestEx(UPDATE_VERSION_URL, "GET", 8, "", true, true, 1u << 20);
    if ((!r.ok || r.body.empty()) && !getSystemProxy().empty())
        r = httpRequestEx(UPDATE_VERSION_URL, "GET", 8, getSystemProxy(), true, true, 1u << 20);
    if (!r.ok || r.code != 200 || r.body.empty()) return "";
    return extractVersion(r.body);
}
// Скачивает репозиторий, собирает linux/ и заменяет программу. Списки, config.json и логи не трогает.
// Возвращает true, если новая программа на месте (тогда её можно перезапустить).
static bool updateSelf() {
    writeLog("Скачивание обновления (только файлы linux/)...", "Cyan");
    if (!haveCmd("make") || !haveCmd("g++")) {
        writeLog("Для обновления нужны make и g++ (и заголовки OpenSSL).", "Red");
        writeLog("  Debian/Ubuntu: sudo apt install build-essential libssl-dev", "White");
        writeLog("  Fedora:        sudo dnf install gcc-c++ make openssl-devel", "White");
        writeLog("  Arch:          sudo pacman -S base-devel openssl", "White");
        return false;
    }
    std::string tmp = g_baseDir + "/_update_tmp";
    runCmd("rm -rf " + shellQuote(tmp) + " 2>/dev/null");
    ensureDirRec(tmp);
    std::string src = tmp;
    // Качаем по отдельности только исходники Linux-версии — не весь репозиторий.
    for (const char* f : UPDATE_FILES) {
        std::string url = UPDATE_RAW_BASE + f;
        if (!downloadFile(url, src + "/" + f) && !getSystemProxy().empty())
            downloadFile(url, src + "/" + f);   // вторая попытка через системный прокси
        if (!pathExists(src + "/" + f)) {
            writeLog(std::string("Не удалось скачать ") + f + " — обновление отменено.", "Red");
            return false;
        }
        writeLog(std::string("  ") + f, "Gray");
    }

    writeLog("Сборка новой версии...", "Cyan");
    if (runAndTee("make -C " + shellQuote(src), "", "Gray") != 0 || access((src + "/lag").c_str(), X_OK) != 0) {
        writeLog("Сборка не удалась — программа осталась прежней.", "Red"); return false;
    }
    // Переносная установка (программа в своей папке рядом с исходниками) — обновляем и исходники.
    if (pathExists(g_exeDir + "/Makefile") && access(g_exeDir.c_str(), W_OK) == 0) {
        if (DIR* d = opendir(src.c_str())) {
            while (dirent* e = readdir(d)) {
                std::string n = e->d_name, from = src + "/" + n;
                if (n == "." || n == ".." || n == "lag" || isDir(from)) continue;
                std::ifstream i(from, std::ios::binary); std::ofstream o(g_exeDir + "/" + n, std::ios::binary);
                o << i.rdbuf();
            }
            closedir(d);
        }
    }
    // Подмена бинарника: пишем рядом и переименовываем — работающую программу это не ломает.
    std::string next = g_exePath + ".new";
    {
        std::ifstream i(src + "/lag", std::ios::binary); std::ofstream o(next, std::ios::binary);
        o << i.rdbuf();
        if (!o) {
            writeLog("Нет прав на запись в " + g_exeDir + ". Новая сборка лежит тут: " + src + "/lag", "Yellow");
            return false;
        }
    }
    chmod(next.c_str(), 0755);
    if (rename(next.c_str(), g_exePath.c_str()) != 0) {
        writeLog("Не удалось заменить " + g_exePath + ": " + strerror(errno), "Red");
        return false;
    }
    runCmd("rm -rf " + shellQuote(tmp) + " 2>/dev/null");
    writeLog("Обновление установлено.", "Green");
    return true;
}

// ================== СТАРТОВЫЕ СПИСКИ ==================
// В отличие от Windows-версии, при первом запуске списки сразу заполняются примерами —
// чтобы проверки работали «из коробки». Свои цели дописывай в эти же файлы.
static void seedList(const std::string& name, const std::string& body) {
    std::string path = g_settingsDir + "/" + name;
    if (pathExists(path)) return;
    std::ofstream o(path, std::ios::binary);
    o << "# Формат: значение;комментарий. Строки с # пропускаются.\n" << body;
}
static void seedDefaults() {
    seedList("sites.txt",
        "youtube.com;YouTube\nt.me;Telegram\ndiscord.com;Discord\ninstagram.com;Instagram\n"
        "x.com;X (Twitter)\nchatgpt.com;ChatGPT\nrutracker.org;RuTracker\nwikipedia.org;Википедия\n"
        "steamcommunity.com;Steam\nya.ru;Яндекс (контроль)\ngosuslugi.ru;Госуслуги (контроль)\n");
    seedList("dns_targets.txt", "8.8.8.8;Google\n1.1.1.1;Cloudflare\n77.88.8.8;Яндекс\n");
    seedList("trace_targets.txt", "1.1.1.1;Cloudflare\nyoutube.com;YouTube\n");
    seedList("scan_targets.txt", "127.0.0.1;этот компьютер\n");
}

// ================== ИНИЦИАЛИЗАЦИЯ ==================
// Где хранить данные: в папке программы (переносная установка), а если туда нельзя
// писать (например, /usr/local/bin) — в ~/.local/share/lag.
static bool lagInit() {
    signal(SIGPIPE, SIG_IGN);   // запись в закрытый сокет не должна убивать программу
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    g_exePath = (n > 0) ? std::string(buf, (size_t)n) : "lag";
    g_exeDir = g_exePath.substr(0, g_exePath.rfind('/'));
    if (g_exeDir.empty()) g_exeDir = ".";
    if (access(g_exeDir.c_str(), W_OK) == 0) g_baseDir = g_exeDir;
    else {
        const char* xdg = getenv("XDG_DATA_HOME");
        const char* home = getenv("HOME");
        if (!home) { passwd* pw = getpwuid(getuid()); home = pw ? pw->pw_dir : "/tmp"; }
        g_baseDir = (xdg && *xdg) ? std::string(xdg) + "/lag" : std::string(home) + "/.local/share/lag";
    }
    g_settingsDir = g_baseDir + "/Settings";
    g_toolsDir    = g_baseDir + "/Tools";
    g_logsDir     = g_baseDir + "/Logs";
    g_configPath  = g_settingsDir + "/config.json";
    ensureDirRec(g_settingsDir);
    ensureDirRec(g_logsDir);
    loadConfig();
    seedDefaults();
    removeOldLogs();
    return true;
}
