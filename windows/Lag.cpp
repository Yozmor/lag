// Lag.cpp — утилита проверки сети (порт PowerShell-скрипта Lagg на C++, Win32)
// VERSION = 5.1
// Сборка: build.bat (g++ + windres для иконки)
// Требует Windows 10/11. Кодировка исходника — UTF-8 (без BOM).

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Windows 10
#endif
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX  // не давать windows.h определять макросы min/max (ломают std::max)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <shellapi.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <regex>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstdint>

// Под MSVC (cl.exe) библиотеки подключаются автоматически — build.bat линковку не задаёт.
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib") // SID/токен (isAdmin) + реестр (RegOpenKeyEx и т.п.)
#pragma comment(lib, "shell32.lib")  // ShellExecuteEx (самоэлевация до админа)
#endif

// ================== ВЕРСИЯ И ССЫЛКИ ОБНОВЛЕНИЯ ==================
static const std::string SCRIPT_VERSION = "5.2";

// Raw-файл, из которого читается строка версии (ищется 'VERSION = x.y' или scriptVersion).
// Windows-версия живёт в папке windows/ репозитория.
static const std::wstring UPDATE_VERSION_URL =
    L"https://raw.githubusercontent.com/Yozmor/lagg/refs/heads/main/windows/Lag.cpp";
// ZIP всего репозитория. Нужные файлы — в подпапке <архив>/windows/.
static const std::wstring UPDATE_ZIP_URL =
    L"https://github.com/Yozmor/lagg/archive/refs/heads/main.zip";
// Подпапка внутри архива, где лежит Windows-версия.
static const std::wstring UPDATE_SUBDIR = L"windows";
// Как называется собранный exe после обновления (должен совпадать с именем файла программы).
static const std::wstring EXE_NAME = L"Lag.exe";

// ================== ЦВЕТА (ANSI/VT) ==================
namespace clr {
    const char* Reset   = "\x1b[0m";
    const char* White   = "\x1b[97m";
    const char* Gray    = "\x1b[90m";
    const char* Red     = "\x1b[91m";
    const char* Green   = "\x1b[92m";
    const char* Yellow  = "\x1b[93m";
    const char* Cyan     = "\x1b[96m";
    const char* Magenta = "\x1b[95m";
}
static const char* colorByName(const std::string& c) {
    if (c=="White")   return clr::White;
    if (c=="Gray")    return clr::Gray;
    if (c=="Red")     return clr::Red;
    if (c=="Green")   return clr::Green;
    if (c=="Yellow")  return clr::Yellow;
    if (c=="Cyan")    return clr::Cyan;
    if (c=="Magenta") return clr::Magenta;
    return clr::White;
}

// ================== ГЛОБАЛЬНЫЕ ПУТИ ==================
static std::wstring g_scriptDir;   // папка с exe
static std::wstring g_settingsDir; // папка Settings (списки .txt + config.json)
static std::wstring g_toolsDir;
static std::wstring g_logsDir;
static std::wstring g_configPath;
static std::wstring g_nexttracePath; // кэш пути (аналог $global:nexttracePath)

// ================== КОНВЕРТАЦИЯ UTF-8 <-> WIDE ==================
static std::wstring toW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
static std::string toU8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// ================== ВЫВОД / ЛОГ ==================
// Сток для оконного режима: каждая строка (цвет, текст) уходит сюда, если задан.
// writeLog вызывается из рабочего потока, поэтому реализация стока должна быть потокобезопасной.
// thread_local — у каждого потока свой сток: несколько проверок идут параллельно,
// и строки каждой попадают только в свой раздел окна.
#include <functional>
static thread_local std::function<void(const std::string& color, const std::string& text)> g_guiSink;
static bool g_guiMode = false;   // true — не писать в консоль (окно без консоли)

static void writeConsole(const std::string& utf8) {
    if (g_guiMode) return;       // в оконном режиме консоли нет
    DWORD written = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
}
static void writeLog(const std::string& text, const std::string& color = "White",
                     const std::wstring& logFile = L"") {
    if (g_guiSink) g_guiSink(color, text);
    std::string line = std::string(colorByName(color)) + text + clr::Reset + "\r\n";
    writeConsole(line);
    if (!logFile.empty()) {
        std::ofstream f(logFile, std::ios::app | std::ios::binary);
        if (f) { std::string t = text + "\r\n"; f.write(t.data(), t.size()); }
    }
}
static std::string readLineU8(const std::string& prompt = "") {
    if (!prompt.empty()) writeConsole(prompt);
    std::string s;
    std::getline(std::cin, s);
    while (!s.empty() && (s.back()=='\r' || s.back()=='\n')) s.pop_back();
    return s;
}
static void pause(const std::string& msg = "\nНажмите Enter для продолжения...") {
    writeLog(msg, "Gray");
    std::string dummy; std::getline(std::cin, dummy);
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
static void tableSep(const std::vector<size_t>& w, const std::wstring& logFile) {
    std::string sep;
    for (size_t c = 0; c < w.size(); c++) { if (c) sep += "-+-"; sep += std::string(w[c], '-'); }
    writeLog(sep, "Gray", logFile);
}
static void tableHead(const std::vector<std::string>& headers,
                      const std::vector<size_t>& w, const std::wstring& logFile) {
    std::string head;
    for (size_t c = 0; c < headers.size(); c++) { if (c) head += " | "; head += padRight(headers[c], w[c]); }
    writeLog(head, "Cyan", logFile);
    tableSep(w, logFile);
}
static void tableRow(const std::vector<std::string>& cells, const std::vector<size_t>& w,
                     const std::string& color, const std::wstring& logFile) {
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
static bool runBlockProbe(const std::wstring& logFile, const std::vector<Item>& targets);
static std::vector<Item> loadItemList(const std::wstring& fileName,
                                      const std::string& headerComment =
                                      "# Список целей\r\n# Формат: значение;комментарий") {
    std::wstring path = g_settingsDir + L"\\" + fileName;
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

// ================== WINSOCK INIT ==================
static bool initWinsock() {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
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

static bool nameLooksVpn(const std::wstring& s) {
    static const wchar_t* kw[] = {L"VPN",L"TAP",L"TUN",L"Wintun",L"WireGuard",
        L"OpenVPN",L"IKEv2",L"PPTP",L"L2TP",L"Amnezia",L"awg",L"Tunnel",L"WG"};
    std::wstring up = s;
    for (auto& c : up) c = towupper(c);
    for (auto k : kw) { std::wstring ku=k; for(auto&c:ku)c=towupper(c);
        if (up.find(ku) != std::wstring::npos) return true; }
    return false;
}

// SSID через wlanapi — загружаем динамически, чтобы сборка не зависела от import-lib.
static std::string getWifiSsid() {
    std::string ssid;
    HMODULE h = LoadLibraryW(L"wlanapi.dll");
    if (!h) return ssid;
    typedef DWORD (WINAPI *pOpen)(DWORD,PVOID,PDWORD,PHANDLE);
    typedef DWORD (WINAPI *pEnum)(HANDLE,PVOID,void**);
    typedef DWORD (WINAPI *pQuery)(HANDLE,const GUID*,int,PVOID,PDWORD,PVOID*,void*);
    typedef VOID  (WINAPI *pFree)(PVOID);
    typedef DWORD (WINAPI *pClose)(HANDLE,PVOID);
    auto WlanOpen  = (pOpen) GetProcAddress(h,"WlanOpenHandle");
    auto WlanEnum  = (pEnum) GetProcAddress(h,"WlanEnumInterfaces");
    auto WlanQuery = (pQuery)GetProcAddress(h,"WlanQueryInterface");
    auto WlanFree  = (pFree) GetProcAddress(h,"WlanFreeMemory");
    auto WlanClose = (pClose)GetProcAddress(h,"WlanCloseHandle");
    if (WlanOpen && WlanEnum && WlanQuery && WlanFree && WlanClose) {
        HANDLE hc = nullptr; DWORD nego = 0;
        if (WlanOpen(2, nullptr, &nego, &hc) == ERROR_SUCCESS) {
            // WLAN_INTERFACE_INFO_LIST: DWORD count; DWORD index; затем массив
            struct IF_INFO { GUID guid; WCHAR desc[256]; int state; };
            void* list = nullptr;
            if (WlanEnum(hc, nullptr, &list) == ERROR_SUCCESS && list) {
                DWORD cnt = *(DWORD*)list;
                BYTE* base = (BYTE*)list + 8;
                for (DWORD i = 0; i < cnt; i++) {
                    IF_INFO* inf = (IF_INFO*)(base + i * sizeof(IF_INFO));
                    // opcode 7 = current_connection
                    void* attr = nullptr; DWORD sz = 0;
                    if (WlanQuery(hc, &inf->guid, 7, nullptr, &sz, &attr, nullptr) == ERROR_SUCCESS && attr) {
                        // WLAN_CONNECTION_ATTRIBUTES: смещение до dot11Ssid.
                        // isState(4) + mode(4) + profile[256*2] + assoc.attributes:
                        //   dot11Ssid: ULONG len; UCHAR ssid[32]  начинается после isState+mode+profileName
                        BYTE* p = (BYTE*)attr;
                        // isState(enum,4) + wlanConnectionMode(enum,4) = 8
                        // strProfileName WCHAR[256] = 512 → далее WLAN_ASSOCIATION_ATTRIBUTES
                        BYTE* assoc = p + 8 + 512;
                        ULONG ssidLen = *(ULONG*)assoc;
                        BYTE* ssidBytes = assoc + 4;
                        if (ssidLen > 0 && ssidLen <= 32) {
                            std::string s((char*)ssidBytes, ssidLen);
                            ssid = s; // SSID в байтах (обычно UTF-8/ASCII)
                        }
                        WlanFree(attr);
                    }
                    if (!ssid.empty()) break;
                }
                WlanFree(list);
            }
            WlanClose(hc, nullptr);
        }
    }
    FreeLibrary(h);
    return ssid;
}

static ConnInfo getConnectionType() {
    ConnInfo r;

    // Получаем все адаптеры
    ULONG sz = 15000;
    std::vector<BYTE> buf(sz);
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, nullptr, aa, &sz);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(sz); aa = (IP_ADAPTER_ADDRESSES*)buf.data();
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr, aa, &sz);
    }
    if (ret != NO_ERROR) return r;

    // 1) активный VPN-адаптер
    for (auto a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        std::wstring fn = a->FriendlyName ? a->FriendlyName : L"";
        std::wstring de = a->Description ? a->Description : L"";
        if (nameLooksVpn(fn) || nameLooksVpn(de)) {
            r.VpnActive = true;
            r.VpnName = sanitizeName(toU8(fn.empty() ? de : fn));
            break;
        }
    }

    // 2) основной физический адаптер: Up, есть шлюз, не VPN, минимальная метрика
    IP_ADAPTER_ADDRESSES* best = nullptr;
    ULONG bestMetric = 0xFFFFFFFF;
    for (auto a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->FirstGatewayAddress == nullptr) continue;
        std::wstring fn = a->FriendlyName ? a->FriendlyName : L"";
        std::wstring de = a->Description ? a->Description : L"";
        if (nameLooksVpn(fn) || nameLooksVpn(de)) continue; // физический — не VPN
        if (a->Ipv4Metric < bestMetric) { bestMetric = a->Ipv4Metric; best = a; }
    }

    if (best) {
        // скорость линка
        if (best->TransmitLinkSpeed && best->TransmitLinkSpeed != (ULONG64)-1) {
            double mbps = best->TransmitLinkSpeed / 1e6;
            std::ostringstream os; os << (long long)mbps << " Mbps";
            r.LinkSpeed = os.str();
        }
        std::wstring fn = best->FriendlyName ? best->FriendlyName : L"";
        if (best->IfType == IF_TYPE_IEEE80211) {
            r.BaseType = "Wi-Fi";
            std::string ssid = getWifiSsid();
            r.Detail = sanitizeName(ssid.empty() ? toU8(fn) : ssid);
        } else if (best->IfType == IF_TYPE_PPP ||
                   best->IfType == 243 /*WWANPP*/ || best->IfType == 244 ||
                   (best->Description && wcsstr(best->Description, L"NDIS"))) {
            r.BaseType = "Модем";
            r.Detail = sanitizeName(toU8(fn));
        } else {
            r.BaseType = "Проводное";
            r.Detail = sanitizeName(toU8(fn));
        }
    }

    // 3) итоговая строка
    r.FullString = r.BaseType;
    if (!r.Detail.empty() && r.Detail != "-") r.FullString += "_" + r.Detail;
    if (r.VpnActive) r.FullString += "+VPN_" + r.VpnName;
    r.FullString = sanitizeName(r.FullString);
    return r;
}

// ================== ИНТЕРФЕЙСЫ И МАРШРУТЫ ==================
struct AdapterInfo {
    DWORD ifIndex = 0;
    std::string name, desc, ipv4, type;
    bool vpnLike = false, hasGw = false;
};
static std::string ifTypeName(DWORD t) {
    switch (t) {
        case IF_TYPE_ETHERNET_CSMACD: return "Ethernet";
        case IF_TYPE_IEEE80211:       return "Wi-Fi";
        case IF_TYPE_SOFTWARE_LOOPBACK: return "Loopback";
        case IF_TYPE_TUNNEL:          return "Туннель";
        case IF_TYPE_PPP:             return "PPP";
        case 53:                      return "Виртуальный";
        case 243: case 244:           return "Моб. модем";
        default:                      return "Другой";
    }
}
// Активные (Up) IPv4-интерфейсы системы.
static std::vector<AdapterInfo> listAdapters() {
    std::vector<AdapterInfo> out;
    ULONG sz = 15000;
    std::vector<BYTE> buf(sz);
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, nullptr, aa, &sz);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(sz); aa = (IP_ADAPTER_ADDRESSES*)buf.data();
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr, aa, &sz);
    }
    if (ret != NO_ERROR) return out;
    for (auto a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        AdapterInfo ai;
        ai.ifIndex = a->IfIndex;
        std::wstring fn = a->FriendlyName ? a->FriendlyName : L"";
        std::wstring de = a->Description  ? a->Description  : L"";
        ai.name = toU8(fn); ai.desc = toU8(de);
        ai.type = ifTypeName(a->IfType);
        ai.vpnLike = nameLooksVpn(fn) || nameLooksVpn(de) ||
                     a->IfType == IF_TYPE_TUNNEL || a->IfType == IF_TYPE_PPP;
        ai.hasGw = (a->FirstGatewayAddress != nullptr);
        for (auto u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)u->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
                ai.ipv4 = ip; break;
            }
        }
        out.push_back(ai);
    }
    return out;
}
// Домен/IP -> первый IPv4-адрес (системный резолвер).
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
struct RouteInfo {
    bool ok = false;
    std::string ip, ifName, ifType, localIp, err;
    bool viaTunnel = false;
};
// Через какой интерфейс ОС отправит пакет до host (по таблице маршрутов).
static RouteInfo routeTo(const std::string& host) {
    RouteInfo r;
    r.ip = resolveIPv4(host);
    if (r.ip.empty()) { r.err = "не резолвится"; return r; }
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(53);
    inet_pton(AF_INET, r.ip.c_str(), &sa.sin_addr);

    DWORD idx = 0;
    if (GetBestInterfaceEx((sockaddr*)&sa, &idx) != NO_ERROR) { r.err = "нет маршрута"; return r; }

    // Локальный адрес-источник: UDP connect() ничего не отправляет, но выбирает маршрут.
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
        if (connect(s, (sockaddr*)&sa, sizeof(sa)) == 0) {
            sockaddr_in loc{}; int len = sizeof(loc);
            if (getsockname(s, (sockaddr*)&loc, &len) == 0) {
                char b[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &loc.sin_addr, b, sizeof(b));
                r.localIp = b;
            }
        }
        closesocket(s);
    }
    for (auto& a : listAdapters()) {
        if (a.ifIndex == idx) {
            r.ifName = a.name; r.ifType = a.type; r.viaTunnel = a.vpnLike;
            if (r.localIp.empty()) r.localIp = a.ipv4;
            break;
        }
    }
    if (r.ifName.empty()) r.ifName = "ifIndex " + std::to_string(idx);
    r.ok = true;
    return r;
}

// IPv4-адрес «служебный» (не годится как цель проверки маршрута)
static bool ipIsSpecial(const in_addr& a) {
    unsigned char b0 = ((const unsigned char*)&a)[0], b1 = ((const unsigned char*)&a)[1];
    if (a.s_addr == 0 || a.s_addr == 0xFFFFFFFF) return true;   // 0.0.0.0, 255.255.255.255
    if (b0 == 127) return true;                                  // loopback
    if (b0 >= 224) return true;                                  // multicast и выше
    if (b0 == 169 && b1 == 254) return true;                     // link-local
    return false;
}
// DNS-серверы, реально прописанные на активных адаптерах: адрес -> имя адаптера.
struct DnsServer { std::string ip, adapter; };
static std::vector<DnsServer> listDnsServers() {
    std::vector<DnsServer> out;
    ULONG sz = 15000;
    std::vector<BYTE> buf(sz);
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_UNICAST;
    ULONG ret = GetAdaptersAddresses(AF_INET, flags, nullptr, aa, &sz);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(sz); aa = (IP_ADAPTER_ADDRESSES*)buf.data();
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr, aa, &sz);
    }
    if (ret != NO_ERROR) return out;
    for (auto a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto d = a->FirstDnsServerAddress; d; d = d->Next) {
            if (d->Address.lpSockaddr->sa_family != AF_INET) continue;
            in_addr ia = ((sockaddr_in*)d->Address.lpSockaddr)->sin_addr;
            if (ia.s_addr == 0) continue;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ia, ip, sizeof(ip));
            bool dup = false;
            for (auto& x : out) if (x.ip == ip) { dup = true; break; }
            if (!dup) out.push_back({ ip, toU8(a->FriendlyName ? a->FriendlyName : L"") });
        }
    }
    return out;
}
// Обходные маршруты: отдельные адреса (/32), которые идут через шлюз физического интерфейса.
// В TUN-режиме VPN-клиент так выводит из туннеля адрес своего сервера — это и есть VPN-сервер.
static std::vector<std::string> listBypassRoutes() {
    std::vector<std::string> out;
    std::map<DWORD, bool> tunnelIf;
    for (auto& a : listAdapters()) tunnelIf[a.ifIndex] = a.vpnLike;
    PMIB_IPFORWARD_TABLE2 t = nullptr;
    if (GetIpForwardTable2(AF_INET, &t) != NO_ERROR || !t) return out;
    for (ULONG i = 0; i < t->NumEntries; i++) {
        const MIB_IPFORWARD_ROW2& r = t->Table[i];
        if (r.DestinationPrefix.PrefixLength != 32) continue;
        if (r.NextHop.Ipv4.sin_addr.s_addr == 0) continue;             // без шлюза = локальная запись
        auto it = tunnelIf.find(r.InterfaceIndex);
        if (it == tunnelIf.end() || it->second) continue;               // интерфейс неактивен или сам туннель
        in_addr dst = r.DestinationPrefix.Prefix.Ipv4.sin_addr;
        if (ipIsSpecial(dst)) continue;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dst, ip, sizeof(ip));
        if (std::find(out.begin(), out.end(), std::string(ip)) == out.end()) out.push_back(ip);
    }
    FreeMibTable(t);
    return out;
}

// Туннель реально несёт трафик, если ему принадлежит маршрут по умолчанию.
// Проба к одному IP (8.8.8.8) ненадёжна: клиенты часто пускают DNS/8.8.8.8 в обход.
// Подпись TUN-клиентов (v2rayTun/sing-box/WireGuard) — сплит 0.0.0.0/1 + 128.0.0.0/1
// вместо замены 0.0.0.0/0. Любой маршрут с префиксом /1 = туннель перехватывает трафик.
// Yggdrasil сюда не попадает: он держит только свою IPv6-сеть (200::/7), не трогает IPv4-дефолт.
static bool defaultViaTunnel() {
    std::map<DWORD, bool> vpn;
    for (auto& a : listAdapters()) vpn[a.ifIndex] = a.vpnLike;
    PMIB_IPFORWARD_TABLE2 t = nullptr;
    if (GetIpForwardTable2(AF_INET, &t) != NO_ERROR || !t) return false;
    bool tun = false;
    for (ULONG i = 0; i < t->NumEntries; i++) {
        const MIB_IPFORWARD_ROW2& r = t->Table[i];
        int pl = r.DestinationPrefix.PrefixLength;
        if (pl == 1) { tun = true; break; }                 // 0/1 или 128/1 — сплит VPN-туннеля
        if (pl == 0) {                                       // полный дефолт на vpn-адаптере
            auto it = vpn.find(r.InterfaceIndex);
            if (it != vpn.end() && it->second) { tun = true; break; }
        }
    }
    FreeMibTable(t);
    return tun;
}

// ================== ПУТЬ К ЛОГУ + ОЧИСТКА ==================
static void ensureDir(const std::wstring& d) {
    CreateDirectoryW(d.c_str(), nullptr); // рекурсию делаем поэтапно ниже
}
static void ensureDirRec(const std::wstring& d) {
    for (size_t i = 3; i < d.size(); i++) {
        if (d[i] == L'\\') { std::wstring sub = d.substr(0,i); CreateDirectoryW(sub.c_str(), nullptr); }
    }
    CreateDirectoryW(d.c_str(), nullptr);
}
static std::wstring nowStamp() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t b[64];
    swprintf(b, 64, L"%04d-%02d-%02d_%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}
static std::wstring getLogFilePath(const std::string& folderKey) {
    ConnInfo ci = getConnectionType();
    std::wstring connFolder = g_logsDir + L"\\" + toW(ci.FullString.empty() ? "Unknown" : ci.FullString);
    std::wstring target = connFolder + L"\\" + toW(folderKey);
    ensureDirRec(target);
    return target + L"\\" + nowStamp() + L".txt";
}
static void removeOldLogs() {
    DWORD attr = GetFileAttributesW(g_logsDir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return;
    FILETIME ftNow; SYSTEMTIME stNow; GetSystemTime(&stNow); SystemTimeToFileTime(&stNow, &ftNow);
    ULARGE_INTEGER now; now.LowPart = ftNow.dwLowDateTime; now.HighPart = ftNow.dwHighDateTime;
    const ULONGLONG dayTicks = 864000000000ULL; // 100ns в сутках
    ULONGLONG cutoff = now.QuadPart - (ULONGLONG)g_config.MaxLogAgeDays * dayTicks;

    int removed = 0;
    std::vector<std::wstring> stack{ g_logsDir };
    while (!stack.empty()) {
        std::wstring dir = stack.back(); stack.pop_back();
        WIN32_FIND_DATAW fd;
        HANDLE hf = FindFirstFileW((dir + L"\\*").c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring name = fd.cFileName;
            if (name == L"." || name == L"..") continue;
            std::wstring full = dir + L"\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { stack.push_back(full); continue; }
            ULARGE_INTEGER w; w.LowPart = fd.ftLastWriteTime.dwLowDateTime; w.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            if (w.QuadPart < cutoff) { if (DeleteFileW(full.c_str())) removed++; }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    if (removed > 0)
        writeLog("Очищено " + std::to_string(removed) + " старых логов (старше " +
                 std::to_string(g_config.MaxLogAgeDays) + " дней).", "Gray");
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
    int r = select(0, nullptr, &wf, nullptr, &tv);
    bool ok = false;
    if (r > 0) {
        int err = 0; int len = sizeof(err);
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
    if (select(0, nullptr, &wf, nullptr, &tv) > 0) {
        int err = 0; int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        if (err == 0) {
            if (port==80 || port==8080) {
                std::string req = "HEAD / HTTP/1.0\r\n\r\n";
                send(s, req.c_str(), (int)req.size(), 0);
            }
            fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
            timeval tv2{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
            if (select(0, &rf, nullptr, nullptr, &tv2) > 0) {
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
static void writeDefaultPorts(const std::wstring& path) {
    std::ofstream o(path, std::ios::binary);
    o << "# Порты для сканирования\r\n# Формат: порт или диапазон от-до;комментарий\r\n";
    for (int p : DEFAULT_PORTS) o << p << ";" << portName(p) << "\r\n";
}
// Порты для скана: из ports.txt (диапазоны разворачиваются, повторы убираются).
static std::vector<int> loadPorts() {
    std::wstring path = g_settingsDir + L"\\ports.txt";
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) writeDefaultPorts(path);
    std::vector<int> out;
    std::vector<bool> seen(65536, false);
    std::ifstream f(path, std::ios::binary);
    std::string line;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.size() >= 3 && (unsigned char)t[0] == 0xEF) t = t.substr(3);   // BOM
        if (t.empty() || t[0] == '#') continue;
        size_t sc = t.find(';');
        int a, b;
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

static bool invokeServiceScan(const std::wstring& logFile, const std::vector<Item>& targets) {
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

// ================== HTTP (WinHTTP) ==================
struct UrlParts { std::wstring host, path; INTERNET_PORT port; bool secure; };
static UrlParts parseUrl(const std::string& raw) {
    std::string u = raw;
    if (!startsWith(u, "http")) u = "https://" + u;
    UrlParts p{}; p.secure = startsWith(u, "https");
    p.port = p.secure ? 443 : 80;
    size_t schemeEnd = u.find("://"); std::string rest = u.substr(schemeEnd + 3);
    size_t slash = rest.find('/');
    std::string hostport = (slash==std::string::npos) ? rest : rest.substr(0, slash);
    p.path = toW((slash==std::string::npos) ? "/" : rest.substr(slash));
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        p.host = toW(hostport.substr(0, colon));
        try { p.port = (INTERNET_PORT)std::stoi(hostport.substr(colon+1)); } catch (...) {}
    } else p.host = toW(hostport);
    return p;
}

// Читаем IE-прокси (то, чем пользуется браузер).
static std::wstring getIEProxy() {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg{};
    std::wstring proxy;
    if (WinHttpGetIEProxyConfigForCurrentUser(&cfg)) {
        if (cfg.lpszProxy) proxy = cfg.lpszProxy;
        if (cfg.lpszProxy)       GlobalFree(cfg.lpszProxy);
        if (cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);
        if (cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);
    }
    return proxy; // может быть "127.0.0.1:10809" или пусто
}

struct HttpResult { int code; long ms; bool ok; std::string body; };
static HttpResult httpRequest(const std::string& url, const std::string& method,
                              int timeoutSec, bool useProxy, const std::wstring& proxyStr,
                              bool wantBody = false) {
    HttpResult res{ 0, 0, false, "" };
    UrlParts u = parseUrl(url);
    auto t0 = std::chrono::steady_clock::now();

    HINTERNET hSession;
    if (useProxy && !proxyStr.empty())
        hSession = WinHttpOpen(L"Lag/5.1", WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                               proxyStr.c_str(), WINHTTP_NO_PROXY_BYPASS, 0);
    else
        hSession = WinHttpOpen(L"Lag/5.1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return res;

    int ms = timeoutSec * 1000;
    WinHttpSetTimeouts(hSession, ms, ms, ms, ms);

    HINTERNET hConnect = WinHttpConnect(hSession, u.host.c_str(), u.port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return res; }

    DWORD flags = u.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConnect, toW(method).c_str(), u.path.c_str(),
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return res; }

    // игнорировать ошибки сертификата (аналог curl -k)
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    // следовать редиректам (аналог -L)
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof(redir));

    bool sent = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
                && WinHttpReceiveResponse(hReq, nullptr);
    if (sent) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        res.code = (int)code; res.ok = true;
        if (wantBody) {
            DWORD avail = 0;
            do {
                avail = 0; WinHttpQueryDataAvailable(hReq, &avail);
                if (avail == 0) break;
                std::vector<char> buf(avail + 1);
                DWORD read = 0;
                if (WinHttpReadData(hReq, buf.data(), avail, &read) && read)
                    res.body.append(buf.data(), read);
            } while (avail > 0);
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    res.ms = (long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return res;
}

// ================== ОПРЕДЕЛЕНИЕ РЕЖИМА VPN + ГЕО ==================
enum class VpnMode { None, Proxy, Tun };
static VpnMode detectVpnMode(std::wstring& proxyOut) {
    proxyOut = getIEProxy();
    DWORD enable = 0, sz = sizeof(enable);
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            0, KEY_READ, &k) == ERROR_SUCCESS) {
        RegQueryValueExW(k, L"ProxyEnable", nullptr, nullptr, (LPBYTE)&enable, &sz);
        RegCloseKey(k);
    }
    if (enable && !proxyOut.empty()) return VpnMode::Proxy; // прокси-режим (Xray/v2rayN и т.п.)
    // TUN-режим = туннель владеет маршрутом по умолчанию (устойчиво к обходу отдельных IP).
    // Просто поднятый TUN (например, Yggdrasil, который ведёт только свою сеть) не считается.
    if (defaultViaTunnel()) return VpnMode::Tun;
    ConnInfo ci = getConnectionType();                      // запасной: активный vpn-адаптер (WFP-режим без своих маршрутов)
    if (ci.VpnActive) return VpnMode::Tun;
    return VpnMode::None;
}
// Внешний IP + страна + провайдер. useProxy=false — напрямую (реальный IP в прокси-режиме).
struct GeoInfo { std::string ip, country, isp; };
static GeoInfo fetchGeo(bool useProxy, const std::wstring& proxy) {
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
    std::wstring proxy = getIEProxy();
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
static bool invokeWebCheck(const std::wstring& logFile) {
    auto sites = loadItemList(L"sites.txt");
    if (sites.empty()) { writeLog("Нет сайтов для проверки. Заполните sites.txt.", "Red", logFile); return false; }
    std::wstring proxy;
    VpnMode mode = detectVpnMode(proxy);
    int timeout = (g_config.HttpTimeout > 0) ? g_config.HttpTimeout : 5;

    writeLog("--- ДОСТУПНОСТЬ САЙТОВ ---", "Green", logFile);
    writeLog("Внешний IP (текущий путь): " + getExternalGeo(), "Cyan", logFile);

    size_t siteW = 4;
    for (auto& it : sites) siteW = std::max(siteW, dispLen(it.Value));
    writeLog("(заблокированные напрямую ждут таймаут " + std::to_string(timeout) + "с — это нормально)", "Gray", logFile);

    if (mode == VpnMode::Proxy) {
        writeLog("Режим VPN: прокси (" + toU8(proxy) + ")", "Cyan", logFile);
        writeLog("", "White", logFile);
        std::vector<std::string> headers = { "Сайт", "Напрямую", "Через VPN" };
        auto w = tableWidths(headers, { siteW, 13, 13 });
        tableHead(headers, w, logFile);
        for (auto& it : sites) {
            HttpResult d = httpRequest(it.Value, "GET", timeout, false, L"");
            HttpResult v = httpRequest(it.Value, "GET", timeout, true, proxy);
            bool rd = httpReachable(d), rv = httpReachable(v);
            std::string col = (!rd && !rv) ? "Red" : ((!rd && rv) ? "Green" : "White");
            tableRow({ it.Value, fmtHttp(d), fmtHttp(v) }, w, col, logFile);
        }
        tableSep(w, logFile);
        writeLog("\nЗелёным — сайты, доступные только через VPN (VPN работает).", "Gray", logFile);
    } else {
        if (mode == VpnMode::Tun)
            writeLog("Режим VPN: туннель (TUN) — весь трафик уже идёт через VPN.", "Cyan", logFile);
        else
            writeLog("VPN не обнаружен (нет ни прокси, ни активного TUN). Проверяю текущий путь.", "Yellow", logFile);
        writeLog("Сверь внешний IP выше со своей страной: чужая страна = туннель несёт трафик.", "Gray", logFile);
        writeLog("", "White", logFile);
        std::vector<std::string> headers = { "Сайт", "Через туннель" };
        auto w = tableWidths(headers, { siteW, 14 });
        tableHead(headers, w, logFile);
        for (auto& it : sites) {
            HttpResult r = httpRequest(it.Value, "GET", timeout, false, L"");
            tableRow({ it.Value, fmtHttp(r) }, w, httpReachable(r) ? "Green" : "Red", logFile);
        }
        tableSep(w, logFile);
        writeLog("\nВ TUN-режиме заблокированные сайты с кодом 200/302 = VPN работает.", "Gray", logFile);
    }
    return true;
}

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
    if (select(0, &rf, nullptr, nullptr, &tv) > 0) {
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

// Системные DNS (первый IPv4)
static std::string getSystemDns() {
    ULONG sz = 15000; std::vector<BYTE> buf(sz);
    IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, aa, &sz) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(sz); aa = (IP_ADAPTER_ADDRESSES*)buf.data();
        GetAdaptersAddresses(AF_INET, 0, nullptr, aa, &sz);
    }
    for (auto a = aa; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (auto d = a->FirstDnsServerAddress; d; d = d->Next) {
            if (d->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                sockaddr_in* si = (sockaddr_in*)d->Address.lpSockaddr;
                inet_ntop(AF_INET, &si->sin_addr, ip, sizeof(ip));
                return ip;
            }
        }
    }
    return "";
}

// ================== ПОЛНАЯ ДИАГНОСТИКА: HTTP + все DNS ==================
static bool invokeWebAndDns(const std::wstring& logFile, const std::vector<Item>& sitesOverride = {}) {
    std::vector<Item> sites = sitesOverride.empty() ? loadItemList(L"sites.txt") : sitesOverride;
    if (sites.empty()) { writeLog("Нет сайтов для диагностики. Заполните sites.txt.", "Red", logFile); return false; }
    auto dnsTargets = loadItemList(L"dns_targets.txt");

    writeLog("\n--- ПОЛНАЯ ДИАГНОСТИКА (HTTP + все DNS) ---", "Green", logFile);
    std::wstring proxy;
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
        HttpResult direct = httpRequest(dom, "GET", timeout, false, L"");
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

// ================== ЗАГРУЗКА ФАЙЛОВ / РАСПАКОВКА ==================
static std::wstring getIEProxy(); // fwd
static bool downloadFile(const std::wstring& url, const std::wstring& dest) {
    UrlParts u = parseUrl(toU8(url));
    // Качаем через системный прокси, если он есть (в прокси-режиме прямой путь может быть заблокирован).
    std::wstring proxy = getIEProxy();
    HINTERNET hS = proxy.empty()
        ? WinHttpOpen(L"Lag/5.1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)
        : WinHttpOpen(L"Lag/5.1", WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                      proxy.c_str(), WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return false;
    WinHttpSetTimeouts(hS, 15000, 15000, 30000, 60000);
    HINTERNET hC = WinHttpConnect(hS, u.host.c_str(), u.port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return false; }
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", u.path.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      u.secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return false; }
    DWORD redir = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hR, WINHTTP_OPTION_REDIRECT_POLICY, &redir, sizeof(redir));
    bool ok = WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
              && WinHttpReceiveResponse(hR, nullptr);
    if (ok) {
        std::ofstream out(dest, std::ios::binary);
        DWORD avail;
        do {
            avail = 0; WinHttpQueryDataAvailable(hR, &avail);
            if (!avail) break;
            std::vector<char> buf(avail);
            DWORD read = 0;
            if (WinHttpReadData(hR, buf.data(), avail, &read) && read) out.write(buf.data(), read);
        } while (avail > 0);
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    return ok;
}

// Запуск процесса и ожидание (без перехвата вывода — наследует консоль).
static DWORD runInherit(const std::wstring& cmdline, const std::wstring& workDir = L"") {
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cl = cmdline;
    DWORD flags = g_guiMode ? CREATE_NO_WINDOW : 0;   // из окна — без мелькающей консоли
    if (!CreateProcessW(nullptr, &cl[0], nullptr, nullptr, TRUE, flags, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi))
        return (DWORD)-1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return code;
}

// Запуск с перехватом вывода: на экран (raw) + в лог (без ANSI).
static std::string stripAnsi(const std::string& s) {
    std::string out; out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '\x1b' && i+1 < s.size() && s[i+1]=='[') {
            i += 2; while (i < s.size() && !(s[i]>='@' && s[i]<='~')) i++; if (i<s.size()) i++;
        } else out.push_back(s[i++]);
    }
    return out;
}
static void runAndTee(const std::wstring& cmdline, const std::wstring& logFile, const std::wstring& workDir = L"") {
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::wstring cl = cmdline;
    // в оконном режиме не открывать чёрное окно консоли для дочернего процесса
    DWORD flags = g_guiMode ? CREATE_NO_WINDOW : 0;
    if (!CreateProcessW(nullptr, &cl[0], nullptr, nullptr, TRUE, flags, nullptr,
                        workDir.empty()?nullptr:workDir.c_str(), &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr); return;
    }
    CloseHandle(wr);
    std::ofstream flog(logFile, std::ios::app | std::ios::binary);
    char buf[4096]; DWORD n;
    std::string guiBuf;  // накапливаем до перевода строки, чтобы слать в окно целыми строками
    while (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n) {
        writeConsole(std::string(buf, n));
        std::string clean = stripAnsi(std::string(buf, n));
        if (flog) flog.write(clean.data(), clean.size());
        if (g_guiSink) {
            guiBuf += clean;
            size_t pos;
            while ((pos = guiBuf.find('\n')) != std::string::npos) {
                std::string ln = guiBuf.substr(0, pos);
                if (!ln.empty() && ln.back() == '\r') ln.pop_back();
                g_guiSink("Gray", ln);
                guiBuf.erase(0, pos + 1);
            }
        }
    }
    if (g_guiSink && !guiBuf.empty()) g_guiSink("Gray", guiBuf);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}

// ================== NEXTTRACE ==================
static std::wstring ensureNextTrace() {
    std::wstring path = g_toolsDir + L"\\nexttrace.exe";
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return path;
    writeLog(" Скачиваю nexttrace.exe ...", "Yellow");
    ensureDirRec(g_toolsDir);
    if (!downloadFile(L"https://github.com/sjlleo/nexttrace/releases/latest/download/nexttrace_windows_amd64.exe", path)) {
        writeLog(" Ошибка скачивания nexttrace.exe", "Red");
        return L"";
    }
    writeLog(" nexttrace.exe загружен.", "Green");
    return path;
}
static bool isAdmin() {
    BOOL admin = FALSE; PSID grp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &grp)) {
        CheckTokenMembership(nullptr, grp, &admin);
        FreeSid(grp);
    }
    return admin;
}

static bool analyzeTrace(const Item& target, const std::wstring& logFile) {
    if (target.Value.empty()) { writeLog("Ошибка: пустая цель трассировки.", "Red", logFile); return false; }
    std::string disp = target.Comment.empty() ? target.Value : (target.Value + " (" + target.Comment + ")");
    writeLog("\n--- ТРАССИРОВКА TCP ДО " + disp + " ---", "Cyan", logFile);

    if (g_nexttracePath.empty()) g_nexttracePath = ensureNextTrace();
    if (g_nexttracePath.empty()) { writeLog("NextTrace недоступен.", "Red", logFile); return false; }

    bool ipv6 = target.Value.find(':') != std::string::npos;
    // Родной realtime-вывод nexttrace с гео, тизвим в лог.
    int hops = (g_config.MaxHops >= 1 && g_config.MaxHops <= 64) ? g_config.MaxHops : 30;  // MaxHops из настроек
    std::wstring cmd = L"\"" + g_nexttracePath + L"\" --tcp --port 443 --language en " +
                       L"--max-hops " + std::to_wstring(hops) + L" " +
                       (ipv6 ? L"--ipv6 " : L"--ipv4 ") + toW(target.Value);
    runAndTee(cmd, logFile);
    return true;
}

// ================== ВНЕШНИЙ IP + СТАРТОВЫЙ ЗАГОЛОВОК ==================
static std::string getExternalIp() {
    std::wstring proxy = getIEProxy();
    // через прокси (покажет IP выхода VPN), иначе напрямую
    HttpResult r = httpRequest("https://api.ipify.org", "GET", 4, !proxy.empty(), proxy, true);
    if (r.ok && !r.body.empty()) return trim(r.body);
    r = httpRequest("https://ifconfig.me/ip", "GET", 4, false, L"", true);
    if (r.ok && !r.body.empty()) return trim(r.body);
    return "Unknown";
}
static std::wstring startReport(const std::string& folderKey) {
    std::wstring logFile = getLogFilePath(folderKey);
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

// ================== ОБНОВЛЕНИЕ ==================
static std::string extractVersion(const std::string& content) {
    std::smatch m;
    if (std::regex_search(content, m, std::regex("VERSION\\s*=\\s*([\\d\\.]+)"))) return m[1];
    if (std::regex_search(content, m, std::regex("scriptVersion\\s*=\\s*\"([\\d\\.]+)\"")))return m[1];
    return "";
}
static std::string fetchRemoteVersion() {
    HttpResult r = httpRequest(toU8(UPDATE_VERSION_URL), "GET", 5, false, L"", true);
    if (!r.ok || r.body.empty()) return "";
    return extractVersion(r.body);
}
static void checkVersionQuiet() {
    std::string rv = fetchRemoteVersion();
    if (!rv.empty() && rv != SCRIPT_VERSION)
        writeLog(" Доступна новая версия: " + rv + " (текущая: " + SCRIPT_VERSION + ").", "Yellow");
}
static void updateSelf() {
    writeLog("\nСкачивание обновления...", "Cyan");
    std::wstring tempZip = g_scriptDir + L"\\_update.zip";
    std::wstring tempDir = g_scriptDir + L"\\_update_tmp";
    if (!downloadFile(UPDATE_ZIP_URL, tempZip)) { writeLog("Ошибка скачивания архива.", "Red"); return; }

    CreateDirectoryW(tempDir.c_str(), nullptr);
    std::wstring cmd = L"tar.exe -xf \"" + tempZip + L"\" -C \"" + tempDir + L"\"";
    if (runInherit(cmd) == (DWORD)-1) {
        std::wstring ps = L"powershell -NoProfile -Command \"Expand-Archive -Path '" + tempZip +
                          L"' -DestinationPath '" + tempDir + L"' -Force\"";
        runInherit(ps);
    }
    // Находим единственную вложенную папку (repo-main)
    std::wstring inner;
    WIN32_FIND_DATAW fd; HANDLE hf = FindFirstFileW((tempDir + L"\\*").c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            std::wstring nm = fd.cFileName;
            if (nm==L"."||nm==L"..") continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { inner = tempDir + L"\\" + nm; break; }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    if (inner.empty()) { writeLog("Не найдена папка с обновлением.", "Red"); return; }

    // Файлы Windows-версии лежат в подпапке windows/ архива. Если её нет
    // (старая раскладка репозитория без папок) — берём корень архива.
    std::wstring srcDir = inner + L"\\" + UPDATE_SUBDIR;
    if (GetFileAttributesW(srcDir.c_str()) == INVALID_FILE_ATTRIBUTES) srcDir = inner;

    // Пишем updater.bat: ждёт выхода exe, копирует новые файлы, перезапускает.
    // ВАЖНО: пользовательские списки (*.txt, config.json) не перезаписываются.
    std::wstring bat = g_scriptDir + L"\\_apply_update.bat";
    std::ofstream b(bat, std::ios::binary);
    std::string innerU = toU8(srcDir);
    std::string dirU   = toU8(g_scriptDir);
    std::string exeU   = toU8(EXE_NAME);
    b << "@echo off\r\n"
      << "chcp 65001 >nul\r\n"
      << "timeout /t 2 /nobreak >nul\r\n"
      // копируем всё, кроме пользовательских данных
      << "robocopy \"" << innerU << "\" \"" << dirU << "\" /E "
         "/XF *.txt config.json /XD Logs Settings >nul\r\n"
      // если в архиве есть готовый exe — заменит; если только исходник, exe пересоберётся вручную
      << "start \"\" \"" << dirU << "\\" << exeU << "\"\r\n"
      << "rmdir /S /Q \"" << toU8(tempDir) << "\" >nul 2>&1\r\n"
      << "del \"" << toU8(tempZip) << "\" >nul 2>&1\r\n"
      << "del \"%~f0\" >nul 2>&1\r\n";
    b.close();

    writeLog("Обновление подготовлено. Программа перезапустится.", "Green");
    std::wstring run = L"cmd.exe /c \"" + bat + L"\"";
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    std::wstring cl = run;
    CreateProcessW(nullptr, &cl[0], nullptr, nullptr, FALSE,
                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    ExitProcess(0);
}
static void checkForUpdates() {
    writeLog("\nПроверка обновлений...", "Cyan");
    std::string rv = fetchRemoteVersion();
    if (rv.empty()) { writeLog(" Не удалось получить версию с GitHub.", "Red"); return; }
    if (rv == SCRIPT_VERSION) { writeLog(" У вас актуальная версия (" + SCRIPT_VERSION + ").", "Green"); return; }
    writeLog(" Доступна новая версия: " + rv + " (текущая: " + SCRIPT_VERSION + ").", "Yellow");
    std::string ch = readLineU8("Хотите обновиться? (y/n): ");
    if (ch=="y"||ch=="Y") updateSelf();
}

// ================== МЕНЮ ==================
static void reportSaved(const std::wstring& logFile) {
    writeLog("\n========================================================", "Cyan", logFile);
    writeLog("Отчёт сохранён в файл:", "Cyan", logFile);
    writeLog("   " + toU8(logFile), "Yellow", logFile);
    writeLog("========================================================", "Cyan", logFile);
    pause();
}
// ================== СОСТОЯНИЕ СЕТИ / VPN ==================
// TCP-соединение с таймаутом; возвращает блокирующий сокет с таймаутами чтения/записи.
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
    if (select(0, nullptr, &wf, nullptr, &tv) > 0) {
        int err = 0; int len = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        ok = (err == 0);
    }
    if (!ok) { closesocket(s); return INVALID_SOCKET; }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    DWORD to = (DWORD)timeoutMs;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
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
static bool parseProxyAddr(const std::wstring& proxyW, std::string& host, int& port) {
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
                       const ProbeResult& pr, bool missingIsProblem, const std::wstring& logFile) {
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

static void writeStateJson(const std::wstring& txtLogFile) {
    if (txtLogFile.empty()) return;
    std::wstring jpath = txtLogFile;                 // .txt -> .json рядом
    size_t dot = jpath.rfind(L'.');
    if (dot != std::wstring::npos) jpath = jpath.substr(0, dot);
    jpath += L".json";

    std::wstring proxyW;
    VpnMode mode = detectVpnMode(proxyW);
    const char* modeStr = (mode == VpnMode::Proxy) ? "proxy" : (mode == VpnMode::Tun) ? "tun" : "none";

    SYSTEMTIME st; GetLocalTime(&st);
    char ts[32];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    GeoInfo direct = fetchGeo(false, L"");
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

static bool invokeNetState(const std::wstring& logFile) {
    writeLog("\n============== СОСТОЯНИЕ СЕТИ / VPN ==============", "Green", logFile);
    std::wstring proxy;
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
        GeoInfo real = fetchGeo(false, L"");
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
        GeoInfo g = fetchGeo(false, L"");
        writeLog("Внешний IP (через туннель): " + fmtGeo(g), "White", logFile);
        writeLog("  -> в TUN-режиме весь трафик идёт через туннель: страна должна быть страной VPN-сервера", "Gray", logFile);
    } else {
        GeoInfo g = fetchGeo(false, L"");
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
        auto sites = loadItemList(L"sites.txt");
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

static void showMenu() {
    writeLog("\n========== МЕНЮ ==========", "Cyan");
    writeLog("1 - Проверить доступность сайтов", "Yellow");
    writeLog("2 - Трассировка", "Yellow");
    writeLog("3 - Сканирование портов", "Yellow");
    writeLog("4 - Состояние сети / VPN", "Yellow");
    writeLog("5 - Настройки", "Yellow");
    writeLog("0 - Выход", "Yellow");
    writeLog("===========================", "Cyan");
}

static void menuSites() {
    for (;;) {
        writeLog("\n========== Доступность сайтов ==========", "Cyan");
        writeLog("1 - Проверить сайты (HTTP: напрямую и через VPN)", "Yellow");
        writeLog("2 - Полная диагностика (HTTP + DNS)", "Yellow");
        writeLog("3 - Полная диагностика (свой хост)", "Yellow");
        writeLog("4 - Диагностика блокировки (SNI-проба)", "Yellow");
        writeLog("0 - Назад", "Yellow");
        std::string c = readLineU8("Выберите действие: ");
        if (c=="0") break;
        bool ok = false; std::wstring lf;
        if (c=="1") { lf = startReport("http"); ok = invokeWebCheck(lf); }
        else if (c=="2") { lf = startReport("dns_full"); ok = invokeWebAndDns(lf); }
        else if (c=="3") {
            std::string custom = readLineU8("Введите IP или домен: ");
            if (!custom.empty()) { lf = startReport("dns_full");
                ok = invokeWebAndDns(lf, { {custom, "Ручной ввод"} }); }
        }
        else if (c=="4") { 
            lf = startReport("block_probe"); 
            ok = runBlockProbe(lf, loadItemList(L"sites.txt")); 
        } else writeLog("Неверный ввод.", "Red");
        if (ok) reportSaved(lf);
    }
}
static void menuTrace() {
    for (;;) {
        writeLog("\n========== Трассировка ==========", "Cyan");
        writeLog("1 - Трассировка (из списка)", "Yellow");
        writeLog("2 - Трассировка (свой хост)", "Yellow");
        writeLog("0 - Назад", "Yellow");
        std::string c = readLineU8("Выберите действие: ");
        if (c=="0") break;
        if ((c=="1"||c=="2") && !isAdmin()) {
            writeLog("Для TCP-трассировки нужны права администратора.", "Red"); continue;
        }
        bool ok = false; std::wstring lf;
        if (c=="1") {
            auto tg = loadItemList(L"trace_targets.txt");
            lf = startReport("trace");
            writeLog("\n--- ТРАССИРОВКА (макс. " + std::to_string(g_config.MaxHops) + " хопов) ---", "Green", lf);
            for (auto& t : tg) ok = analyzeTrace(t, lf) || ok;
        } else if (c=="2") {
            std::string custom = readLineU8("Введите IP или домен: ");
            if (!custom.empty()) { lf = startReport("trace"); ok = analyzeTrace({custom, ""}, lf); }
        } else writeLog("Неверный ввод.", "Red");
        if (ok) reportSaved(lf);
    }
}
static void menuScan() {
    for (;;) {
        writeLog("\n========== Сканирование портов ==========", "Cyan");
        writeLog("1 - Сканирование (из списка)", "Yellow");
        writeLog("2 - Сканирование (свой хост)", "Yellow");
        writeLog("0 - Назад", "Yellow");
        std::string c = readLineU8("Выберите действие: ");
        if (c=="0") break;
        bool ok = false; std::wstring lf;
        if (c=="1") {
            auto tg = loadItemList(L"scan_targets.txt");
            lf = startReport("service_scan"); ok = invokeServiceScan(lf, tg);
        } else if (c=="2") {
            std::string custom = readLineU8("Введите IP или домен: ");
            if (!custom.empty()) { lf = startReport("service_scan");
                ok = invokeServiceScan(lf, { {custom, ""} }); }
        } else writeLog("Неверный ввод.", "Red");
        if (ok) reportSaved(lf);
    }
}
static int askInt(const std::string& prompt, int cur) {
    std::string v = readLineU8(prompt);
    if (std::regex_match(v, std::regex("^\\d+$"))) { try { return std::stoi(v); } catch (...) {} }
    writeLog("Неверный ввод", "Red"); return cur;
}
static void menuSettings() {
    for (;;) {
        writeLog("\n========== Настройки ==========", "Cyan");
        writeLog("1 - Показать текущие настройки", "Yellow");
        writeLog("2 - Таймаут соединения (сейчас " + std::to_string(g_config.ConnectionTimeout) + " мс)", "Yellow");
        writeLog("3 - Таймаут чтения баннера (сейчас " + std::to_string(g_config.BannerTimeout) + " мс)", "Yellow");
        writeLog("4 - Таймаут HTTP-запроса (сейчас " + std::to_string(g_config.HttpTimeout) + " сек)", "Yellow");
        writeLog("5 - Период хранения логов (сейчас " + std::to_string(g_config.MaxLogAgeDays) + " дней)", "Yellow");
        writeLog("6 - Сбросить настройки по умолчанию", "Yellow");
        writeLog("7 - Проверить обновления", "Yellow");
        writeLog("0 - Назад", "Yellow");
        std::string c = readLineU8("Выберите действие: ");
        if (c=="0") break;
        if (c=="1") {
            writeLog("\nConnectionTimeout: " + std::to_string(g_config.ConnectionTimeout) + " мс — TCP-connect при скане портов.", "White");
            writeLog("BannerTimeout: " + std::to_string(g_config.BannerTimeout) + " мс — ожидание баннера.", "White");
            writeLog("HttpTimeout: " + std::to_string(g_config.HttpTimeout) + " сек — таймаут HTTP.", "White");
            writeLog("MaxLogAgeDays: " + std::to_string(g_config.MaxLogAgeDays) + " дней — срок хранения логов.", "White");
            pause();
        } else if (c=="2") { g_config.ConnectionTimeout = askInt("Новый таймаут соединения (мс): ", g_config.ConnectionTimeout); saveConfig(); }
        else if (c=="3") { g_config.BannerTimeout = askInt("Новый таймаут баннера (мс): ", g_config.BannerTimeout); saveConfig(); }
        else if (c=="4") { g_config.HttpTimeout = askInt("Новый таймаут HTTP (сек): ", g_config.HttpTimeout); saveConfig(); }
        else if (c=="5") { g_config.MaxLogAgeDays = askInt("Период хранения логов (дней): ", g_config.MaxLogAgeDays); saveConfig(); }
        else if (c=="6") { g_config = Config{}; saveConfig(); writeLog("Настройки сброшены.", "Green"); }
        else if (c=="7") { checkForUpdates(); }
        else writeLog("Неверный ввод.", "Red");
    }
}

// ================== MAIN ==================
static void enableVT() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0; GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
// Если запущены без прав администратора — перезапускаем себя с UAC (нужно для трассировки).
static void ensureAdmin() {
    if (isAdmin()) return;
    wchar_t path[MAX_PATH]; GetModuleFileNameW(nullptr, path, MAX_PATH);
    SHELLEXECUTEINFOW sei{}; sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";      // запрос повышения прав
    sei.lpFile = path;
    sei.nShow  = SW_SHOWNORMAL;
    if (ShellExecuteExW(&sei)) ExitProcess(0); // ушли в elevated-копию
    // если пользователь отказался от UAC — продолжаем без прав (трасса не сработает)
}
// Инициализация путей, миграция настроек, Winsock, конфиг, очистка логов.
// Вызывается и консольным main, и оконным wWinMain.
static bool lagInit() {
    wchar_t buf[MAX_PATH];
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring exePath = buf;
    g_scriptDir  = exePath.substr(0, exePath.find_last_of(L"\\/"));
    g_settingsDir= g_scriptDir + L"\\Settings";
    g_toolsDir   = g_scriptDir + L"\\Tools";
    g_logsDir    = g_scriptDir + L"\\Logs";
    g_configPath = g_settingsDir + L"\\config.json";
    SetCurrentDirectoryW(g_scriptDir.c_str());
    ensureDirRec(g_settingsDir);
    // Миграция: переносим оставшиеся в корне файлы настроек в папку Settings.
    const wchar_t* names[] = { L"config.json", L"sites.txt",
        L"trace_targets.txt", L"scan_targets.txt", L"dns_targets.txt" };
    for (auto nm : names) {
        std::wstring src = g_scriptDir + L"\\" + nm;
        std::wstring dst = g_settingsDir + L"\\" + nm;
        if (GetFileAttributesW(src.c_str()) != INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesW(dst.c_str()) == INVALID_FILE_ATTRIBUTES) {
            if (!MoveFileW(src.c_str(), dst.c_str()))
                CopyFileW(src.c_str(), dst.c_str(), TRUE);
        }
    }
    if (!initWinsock()) return false;
    loadConfig();
    removeOldLogs();
    return true;
}

int consoleMain() {
    ensureAdmin();
    SetConsoleTitleW(L"Lag");
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    enableVT();
    if (!lagInit()) { writeLog("Ошибка инициализации Winsock.", "Red"); return 1; }

    for (;;) {
        writeLog("\nVersion " + SCRIPT_VERSION, "Gray");
        checkVersionQuiet();
        showMenu();
        std::string c = readLineU8("Выберите действие: ");
        if (c=="0") { writeLog("Работа завершена.", "Green"); break; }
        else if (c=="1") menuSites();
        else if (c=="2") menuTrace();
        else if (c=="3") menuScan();
        else if (c=="4") { auto lf = startReport("netstate"); if (invokeNetState(lf)) reportSaved(lf); }
        else if (c=="5") menuSettings();
        else writeLog("Неверный ввод.", "Red");
    }

    WSACleanup();
    return 0;
}
