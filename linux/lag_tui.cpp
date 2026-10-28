// lag_tui.cpp — терминальный интерфейс Lag для Linux по макету Windows-версии.
// Чистый ANSI + termios, без ncurses: одна самодостаточная программа.
// Включается последним (lag.cpp подключает core, probe, tui).
//
// Экраны: ГЛАВНАЯ (состояние + быстрый запуск + последние отчёты),
// разделы с живым логом (Сайты, DNS, ЗОНД, Трасса, Порты, Сеть/VPN),
// Настройки, Обновление. Tab — фокус меню/окно, ↑↓ — пункт, Enter — запуск,
// 1-8 — быстрый выбор, Q — выход.

#include <termios.h>
#include <sys/ioctl.h>
#include <poll.h>

// ---------- палитра (ANSI 256) ----------
namespace ui {
    const char* RESET = "\x1b[0m";
    const char* AMBER = "\x1b[38;5;215m";   // акцент/логотип
    const char* AMBERD= "\x1b[38;5;137m";   // приглушённый янтарь
    const char* TEAL  = "\x1b[38;5;80m";    // рамки/заголовки
    const char* TEALD = "\x1b[38;5;66m";
    const char* DIM   = "\x1b[38;5;244m";
    const char* TX    = "\x1b[38;5;252m";
    const char* GREEN = "\x1b[38;5;114m";
    const char* RED   = "\x1b[38;5;203m";
    const char* YELLOW= "\x1b[38;5;221m";
    const char* CYAN  = "\x1b[38;5;80m";
    const char* MAG   = "\x1b[38;5;176m";
    const char* BG    = "\x1b[48;5;233m";   // тёмный фон панелей
}
static const char* logColor(const std::string& c) {
    if (c == "Red")     return ui::RED;
    if (c == "Green")   return ui::GREEN;
    if (c == "Yellow")  return ui::YELLOW;
    if (c == "Cyan")    return ui::CYAN;
    if (c == "Magenta") return ui::MAG;
    if (c == "Gray")    return ui::DIM;
    return ui::TX;
}

// ================== РАЗДЕЛЫ ==================
enum Screen { SCR_HOME = -1, SCR_SITES, SCR_DNS, SCR_ZOND, SCR_TRACE, SCR_PORTS, SCR_NET,
              SCR_SETTINGS, SCR_UPDATE, SCR_COUNT };
struct MenuItem { const char* name; const char* folderKey; const char* hint; };
static const MenuItem MENU[SCR_COUNT] = {
    { "Сайты",       "http",         "доступность: DoH + TLS с SNI" },
    { "DNS",         "dns_full",     "HTTP + сравнение DNS-ответов" },
    { "ЗОНД",        "block_probe",  "тип блока: DNS/IP/SNI + NAT" },
    { "Трассировка", "trace",        "TCP до цели, гео узлов" },
    { "Порты",       "service_scan", "баннеры, версии, CVE" },
    { "Сеть / VPN",  "netstate",     "IP, маршруты, утечки" },
    { "Настройки",   "",             "таймауты, сроки, SOCKS-порт" },
    { "Обновление",  "",             "проверить версию на GitHub" },
};
static bool isRunnable(int s) { return s >= SCR_SITES && s <= SCR_NET; }

// ================== ЖИВОЙ ЛОГ РАЗДЕЛА ==================
struct LogLine { std::string color, text; };
static std::mutex g_logMx;
static std::vector<LogLine> g_log[SCR_COUNT];
static std::atomic<bool> g_busy{false};
static std::atomic<int>  g_runScr{SCR_HOME};
static std::atomic<bool> g_dirty{true};
static int g_scroll[SCR_COUNT] = {0};
static std::atomic<bool> g_follow{true};   // автопрокрутка к низу во время прогона

static void logPush(int scr, const std::string& color, const std::string& text) {
    std::lock_guard<std::mutex> lk(g_logMx);
    // ядро иногда шлёт строку с '\n' внутри — режем
    size_t a = 0;
    while (true) {
        size_t b = text.find('\n', a);
        std::string part = text.substr(a, b == std::string::npos ? std::string::npos : b - a);
        if (!part.empty() && part.back() == '\r') part.pop_back();
        g_log[scr].push_back({ color, part });
        if (b == std::string::npos) break;
        a = b + 1;
    }
    g_dirty = true;
}

// Запуск раздела в рабочем потоке. Одна проверка за раз (как в Windows-версии).
static void startRun(int scr) {
    if (!isRunnable(scr) || g_busy) return;
    { std::lock_guard<std::mutex> lk(g_logMx); g_log[scr].clear(); }
    g_scroll[scr] = 0; g_follow = true; g_busy = true; g_runScr = scr; g_dirty = true;
    std::thread([scr] {
        g_guiSink = [scr](const std::string& c, const std::string& t) { logPush(scr, c, t); };
        std::string lf = startReport(MENU[scr].folderKey);
        switch (scr) {
            case SCR_SITES: runSitesCheck(lf, loadItemList("sites.txt")); break;
            case SCR_DNS:   invokeWebAndDns(lf); break;
            case SCR_ZOND:  runBlockProbe(lf, loadItemList("sites.txt")); break;
            case SCR_PORTS: invokeServiceScan(lf, loadItemList("scan_targets.txt")); break;
            case SCR_NET:   invokeNetState(lf); break;
            case SCR_TRACE: {
                auto tg = loadItemList("trace_targets.txt");
                if (tg.empty()) writeLog("Список trace_targets.txt пуст.", "Yellow", lf);
                for (auto& t : tg) analyzeTrace(t, lf);
                break;
            }
        }
        writeLog("", "Gray", lf);
        writeLog("Отчёт сохранён: " + lf, "Cyan", lf);
        g_guiSink = nullptr;
        g_busy = false; g_dirty = true;
    }).detach();
}

// ================== РЕНДЕР ==================
static int g_rows = 24, g_cols = 100;
static void termSize() {
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) { g_rows = ws.ws_row; g_cols = ws.ws_col; }
}
static termios g_oldt;
static void termRaw() {
    tcgetattr(STDIN_FILENO, &g_oldt);
    termios t = g_oldt;
    t.c_lflag &= ~(ICANON | ECHO);
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
    printf("\x1b[?1049h\x1b[?25l");   // альт-экран + спрятать курсор
    fflush(stdout);
}
static void termRestore() {
    printf("\x1b[?25h\x1b[?1049l");
    fflush(stdout);
    tcsetattr(STDIN_FILENO, TCSANOW, &g_oldt);
}

// обрезка строки по видимой ширине (UTF-8)
static std::string clip(const std::string& s, size_t w) {
    std::string out; size_t n = 0;
    for (size_t i = 0; i < s.size() && n < w;) {
        unsigned char c = (unsigned char)s[i];
        int len = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 1;
        out.append(s, i, len); i += len; n++;
    }
    return out;
}
static void mv(int r, int c) { printf("\x1b[%d;%dH", r, c); }
// рамка с заголовком
static void box(int r, int c, int w, int h, const std::string& title, const char* col) {
    mv(r, c); printf("%s┌", col);
    for (int i = 0; i < w - 2; i++) printf("─");
    printf("┐");
    for (int y = 1; y < h - 1; y++) { mv(r + y, c); printf("│"); mv(r + y, c + w - 1); printf("│"); }
    mv(r + h - 1, c); printf("└");
    for (int i = 0; i < w - 2; i++) printf("─");
    printf("┘%s", ui::RESET);
    if (!title.empty()) { mv(r, c + 2); printf(" %s%s %s", col, title.c_str(), ui::RESET); }
}

static std::string nowClock() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[48]; snprintf(b, sizeof(b), "%02d.%02d.%04d  %02d:%02d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
    return b;
}

// Снимок состояния для «шапки» главной (кэш, чтобы не дёргать сеть на каждый кадр).
struct HomeState { std::string conn, speed, ip, geo, vpnMode, vpnAddr; bool have = false; };
static HomeState g_home;
static std::atomic<bool> g_homeLoading{false};
static void refreshHome() {
    if (g_homeLoading.exchange(true)) return;
    std::thread([] {
        HomeState h;
        ConnInfo ci = getConnectionType();
        h.conn = ci.BaseType + (ci.Detail != "-" && !ci.Detail.empty() ? "  " + ci.Detail : "");
        h.speed = ci.LinkSpeed;
        std::string proxy; VpnMode m = detectVpnMode(proxy);
        h.vpnMode = (m == VpnMode::Proxy) ? "прокси" : (m == VpnMode::Tun) ? "туннель (TUN)" : "не найден";
        if (m == VpnMode::Proxy) h.vpnAddr = proxy;
        else if (ci.VpnActive) h.vpnAddr = "адаптер: " + ci.VpnName;
        GeoInfo g = fetchGeo(m == VpnMode::Proxy, proxy);
        h.ip = g.ip.empty() ? "—" : g.ip;
        h.geo = g.country;
        if (m != VpnMode::None && !g.country.empty()) h.geo += "  · через VPN";
        h.have = true;
        g_home = h; g_dirty = true; g_homeLoading = false;
    }).detach();
}

// последние отчёты: читаем дерево Logs
struct RepRow { std::string when, scr, size; time_t t; };
static std::vector<RepRow> recentReports(int limit) {
    std::vector<RepRow> out;
    if (limit < 0) limit = 0;
    std::vector<std::string> stack{ g_logsDir };
    std::vector<std::pair<std::string, std::string>> files;   // путь, folderKey
    while (!stack.empty()) {
        std::string d = stack.back(); stack.pop_back();
        DIR* dir = opendir(d.c_str()); if (!dir) continue;
        while (dirent* e = readdir(dir)) {
            std::string n = e->d_name; if (n == "." || n == "..") continue;
            std::string full = d + "/" + n;
            struct stat st; if (stat(full.c_str(), &st) != 0) continue;
            if (S_ISDIR(st.st_mode)) stack.push_back(full);
            else if (n.size() > 4 && n.substr(n.size() - 4) == ".txt") {
                std::string key = d.substr(d.rfind('/') + 1);
                files.push_back({ full, key });
            }
        }
        closedir(dir);
    }
    for (auto& f : files) {
        struct stat st; if (stat(f.first.c_str(), &st) != 0) continue;
        RepRow r; r.t = st.st_mtime;
        std::string scr = f.second;
        for (int i = 0; i < SCR_COUNT; i++) if (MENU[i].folderKey == scr) { scr = MENU[i].name; break; }
        r.scr = scr;
        SYSTEMTIME now; GetLocalTime(&now);
        struct tm lt; localtime_r(&st.st_mtime, &lt);
        char b[32];
        time_t today = time(nullptr) - (time(nullptr) % 86400);
        if (st.st_mtime >= today) snprintf(b, sizeof(b), "сегодня %02d:%02d", lt.tm_hour, lt.tm_min);
        else snprintf(b, sizeof(b), "%02d.%02d %02d:%02d", lt.tm_mday, lt.tm_mon + 1, lt.tm_hour, lt.tm_min);
        r.when = b;
        long kb = (st.st_size + 1023) / 1024;
        r.size = std::to_string(kb) + " КБ";
        out.push_back(r);
    }
    std::sort(out.begin(), out.end(), [](const RepRow& a, const RepRow& b) { return a.t > b.t; });
    if ((int)out.size() > limit) out.resize(limit);
    return out;
}

static int g_sel = 0;       // выбранный пункт меню (0..SCR_COUNT-1 -> SCR_SITES..)
static int g_screen = SCR_HOME;
static int g_focus = 0;     // 0 — меню, 1 — окно
static std::string g_flash; // строка статуса снизу

static void drawHeader() {
    mv(1, 2); printf("%s◣%s %sLag%s  %s· диагностика сети и VPN%s",
                     ui::AMBER, ui::RESET, ui::AMBER, ui::RESET, ui::TEAL, ui::RESET);
    mv(2, 2); printf("%sпрокси · TUN · DNS · трассировка · порты%s", ui::DIM, ui::RESET);
    std::string clock = nowClock();
    mv(1, g_cols - (int)clip(clock, 99).size() - 1); printf("%s%s%s", ui::DIM, clock.c_str(), ui::RESET);
    std::string who = isAdmin() ? "ROOT ●" : "пользователь ●";
    mv(2, g_cols - (int)clip(who, 99).size() - 1);
    printf("%s%s%s", isAdmin() ? ui::GREEN : ui::DIM, who.c_str(), ui::RESET);
    mv(3, 2); printf("%s", ui::TEALD);
    for (int i = 0; i < g_cols - 2; i++) printf("─");
    printf("%s", ui::RESET);
}

static void drawMenu() {
    int top = 5, mw = 22;
    box(top, 2, mw, g_rows - top - 2, "МЕНЮ", g_focus == 0 ? ui::AMBER : ui::TEALD);
    for (int i = 0; i < SCR_COUNT; i++) {
        int y = top + 2 + i + (i >= SCR_SETTINGS ? 1 : 0);   // отступ перед Настройками
        bool cur = (g_focus == 0 && g_sel == i);
        mv(y, 4);
        const char* num = ui::AMBER;
        const char* nm = cur ? ui::TX : ui::DIM;
        if (cur) printf("%s▸ %s", ui::AMBER, ui::RESET);
        else printf("  ");
        printf("%s%d%s  %s%s%s", num, i + 1, ui::RESET, nm, MENU[i].name, ui::RESET);
    }
    int qy = top + 2 + SCR_COUNT + 1;
    mv(qy, 4); printf("%s0  Выход%s", ui::DIM, ui::RESET);
    mv(g_rows - 4, 4); printf("%sTab%s %sфокус%s", ui::AMBERD, ui::RESET, ui::DIM, ui::RESET);
}

static void drawFooter(const std::string& keys) {
    mv(g_rows - 1, 2);
    printf("%s%s%s", ui::DIM, clip(keys, g_cols - 3).c_str(), ui::RESET);
    printf("\x1b[K");
    if (!g_flash.empty()) { mv(g_rows, 2); printf("%s%s%s\x1b[K", ui::YELLOW, clip(g_flash, g_cols - 3).c_str(), ui::RESET); }
    else { mv(g_rows, 2); printf("\x1b[K"); }
}

static void drawHomeContent(int cx, int cw) {
    int top = 5;
    box(top, cx, cw, g_rows - top - 2, "СОСТОЯНИЕ", g_focus == 1 ? ui::AMBER : ui::TEALD);
    // три карточки
    int bw = (cw - 6) / 3, by = top + 2;
    const char* titles[3] = { "ПОДКЛЮЧЕНИЕ", "ВНЕШНИЙ IP", "РЕЖИМ VPN" };
    for (int i = 0; i < 3; i++) box(by, cx + 2 + i * (bw + 1), bw, 5, titles[i], ui::TEALD);
    if (!g_home.have) {
        mv(by + 2, cx + 4); printf("%sопределяю…%s", ui::DIM, ui::RESET);
    } else {
        int c0 = cx + 2, c1 = cx + 2 + (bw + 1), c2 = cx + 2 + 2 * (bw + 1);
        mv(by + 2, c0 + 2); printf("%s%s%s", ui::TX, clip(g_home.conn, bw - 4).c_str(), ui::RESET);
        mv(by + 3, c0 + 2); printf("%s%s%s", ui::TEAL, clip(g_home.speed.empty() ? "" : g_home.speed, bw - 4).c_str(), ui::RESET);
        mv(by + 2, c1 + 2); printf("%s%s%s", ui::TX, clip(g_home.ip, bw - 4).c_str(), ui::RESET);
        mv(by + 3, c1 + 2); printf("%s%s%s", ui::TEAL, clip(g_home.geo, bw - 4).c_str(), ui::RESET);
        const char* vc = g_home.vpnMode == "не найден" ? ui::YELLOW : ui::TX;
        mv(by + 2, c2 + 2); printf("%s%s%s", vc, clip(g_home.vpnMode, bw - 4).c_str(), ui::RESET);
        mv(by + 3, c2 + 2); printf("%s%s%s", ui::TEAL, clip(g_home.vpnAddr, bw - 4).c_str(), ui::RESET);
    }
    // быстрый запуск
    int qy = by + 6;
    mv(qy, cx + 2); printf("%sРАЗДЕЛЫ (Enter — запустить выбранный)%s", ui::TEAL, ui::RESET);
    for (int i = 0; i < 6; i++) {
        mv(qy + 1 + i, cx + 4);
        printf("%s%d%s  %s%s%s  %s%s%s", ui::AMBER, i + 1, ui::RESET,
               ui::TX, padRight(MENU[i].name, 13).c_str(), ui::RESET, ui::DIM, MENU[i].hint, ui::RESET);
    }
    // последние отчёты
    int ry = qy + 8;
    mv(ry, cx + 2); printf("%sПОСЛЕДНИЕ ОТЧЁТЫ%s", ui::TEAL, ui::RESET);
    auto reps = recentReports(g_rows - ry - 5);
    if (reps.empty()) { mv(ry + 1, cx + 4); printf("%sещё нет — запусти любую проверку%s", ui::DIM, ui::RESET); }
    for (size_t i = 0; i < reps.size(); i++) {
        mv(ry + 1 + i, cx + 4);
        printf("%s%-14s%s %s%s%s  %s%s%s", ui::DIM, reps[i].when.c_str(), ui::RESET,
               ui::AMBERD, padRight(clip(reps[i].scr, 13), 13).c_str(), ui::RESET, ui::DIM, reps[i].size.c_str(), ui::RESET);
    }
}

static void drawRunContent(int scr, int cx, int cw) {
    int top = 5, ch = g_rows - top - 2;
    std::string title = std::string(MENU[scr].name);
    const char* fcol = g_focus == 1 ? ui::AMBER : ui::TEALD;
    box(top, cx, cw, ch, title + "  //  " + MENU[scr].hint, fcol);
    // строка запуска
    mv(top + 1, cx + 2);
    bool running = g_busy && g_runScr == scr;
    if (running) printf("%s● идёт проверка…%s", ui::GREEN, ui::RESET);
    else if (g_busy) printf("%s● занято: идёт другая проверка — дождись%s", ui::YELLOW, ui::RESET);
    else printf("%s▶ ЗАПУСТИТЬ%s  %s[Enter]%s", ui::AMBER, ui::RESET, ui::DIM, ui::RESET);
    // лог
    int ly = top + 3, lh = ch - 4, lw = cw - 4;
    std::lock_guard<std::mutex> lk(g_logMx);
    auto& L = g_log[scr];
    int total = (int)L.size();
    if (g_follow && running) g_scroll[scr] = std::max(0, total - lh);
    int start = std::min(g_scroll[scr], std::max(0, total - lh));
    if (start < 0) start = 0;
    for (int i = 0; i < lh; i++) {
        mv(ly + i, cx + 2);
        printf("\x1b[K");
        int idx = start + i;
        if (idx < total) printf("%s%s%s", logColor(L[idx].color), clip(L[idx].text, lw).c_str(), ui::RESET);
    }
    if (total > lh) {
        mv(ly, cx + cw - 3); printf("%s▲%s", ui::DIM, ui::RESET);
        mv(ly + lh - 1, cx + cw - 3); printf("%s▼%s", ui::DIM, ui::RESET);
    }
}

// ---------- Настройки ----------
struct SetItem { const char* name; int* val; int lo, hi, step; const char* unit; };
static std::vector<SetItem> settingItems() {
    return {
        { "Таймаут TCP-connect", &g_config.ConnectionTimeout, 100, 10000, 100, "мс" },
        { "Таймаут баннера",     &g_config.BannerTimeout,     100, 10000, 100, "мс" },
        { "Таймаут HTTP/проб",   &g_config.HttpTimeout,       1,   30,    1,   "с"  },
        { "Хранить логи",        &g_config.MaxLogAgeDays,     1,   3650,  10,  "дн" },
        { "Максимум хопов",      &g_config.MaxHops,           5,   64,    1,   ""   },
        { "SOCKS-порт (0=авто)", &g_config.SocksPort,         0,   65535, 1,   ""   },
    };
}
static int g_setSel = 0;
static void drawSettings(int cx, int cw) {
    int top = 5;
    box(top, cx, cw, g_rows - top - 2, "НАСТРОЙКИ  //  ←→ менять · S сохранить", g_focus == 1 ? ui::AMBER : ui::TEALD);
    auto items = settingItems();
    for (size_t i = 0; i < items.size(); i++) {
        int y = top + 2 + (int)i * 2;
        bool cur = (g_focus == 1 && g_setSel == (int)i);
        mv(y, cx + 3);
        printf("%s%s%-24s%s", cur ? ui::AMBER : ui::DIM, cur ? "▸ " : "  ", items[i].name, ui::RESET);
        mv(y, cx + 32);
        printf("%s%s%d %s%s", cur ? ui::TX : ui::TEAL, cur ? "◂ " : "  ", *items[i].val, items[i].unit, ui::RESET);
        if (cur) printf(" %s▸%s", ui::TX, ui::RESET);
    }
    mv(g_rows - 5, cx + 3); printf("%sЗначения действуют сразу; S — записать в config.json.%s", ui::DIM, ui::RESET);
}

// ---------- Обновление ----------
static std::atomic<bool> g_updBusy{false};
static std::string g_updMsg = "Нажми Enter — проверю версию на GitHub.";
static void drawUpdate(int cx, int cw) {
    int top = 5;
    box(top, cx, cw, g_rows - top - 2, "ОБНОВЛЕНИЕ", g_focus == 1 ? ui::AMBER : ui::TEALD);
    mv(top + 2, cx + 3); printf("%sТекущая версия: %s%s", ui::DIM, ui::TX, SCRIPT_VERSION.c_str());
    mv(top + 4, cx + 3); printf("%s%s%s", ui::TX, clip(g_updMsg, cw - 6).c_str(), ui::RESET);
    mv(top + 6, cx + 3);
    if (g_updBusy) printf("%s● работаю…%s", ui::YELLOW, ui::RESET);
    else printf("%s▶ Проверить / обновить%s  %s[Enter]%s", ui::AMBER, ui::RESET, ui::DIM, ui::RESET);
}

static void render() {
    printf("\x1b[2J");
    if (g_rows < 20 || g_cols < 80) {
        mv(1, 1); printf("%sLag%s — увеличь окно терминала.", ui::AMBER, ui::RESET);
        mv(2, 1); printf("%sНужно минимум 80×20, сейчас %d×%d. Для скриптов: lag --run <раздел>.%s",
                         ui::DIM, g_cols, g_rows, ui::RESET);
        fflush(stdout);
        return;
    }
    drawHeader();
    drawMenu();
    int cx = 26, cw = g_cols - cx - 1;
    std::string keys;
    if (g_screen == SCR_HOME) {
        drawHomeContent(cx, cw);
        keys = "↑↓ выбрать раздел   Enter запустить   1-8 переключить   Q выход";
    } else if (isRunnable(g_screen)) {
        drawRunContent(g_screen, cx, cw);
        keys = "Enter запустить   Tab окно (прокрутка)   ↑↓ листать   Esc главная   Q выход";
    } else if (g_screen == SCR_SETTINGS) {
        drawSettings(cx, cw);
        keys = "↑↓ параметр   ←→ значение   S сохранить   Esc назад   Q выход";
    } else if (g_screen == SCR_UPDATE) {
        drawUpdate(cx, cw);
        keys = "Enter проверить/обновить   Esc назад   Q выход";
    }
    drawFooter(keys);
    fflush(stdout);
}

// ================== ВВОД ==================
enum Key { K_NONE, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_ENTER, K_ESC, K_TAB, K_CHAR };
static int readKey(char& ch) {
    pollfd p{ STDIN_FILENO, POLLIN, 0 };
    if (poll(&p, 1, 200) <= 0) return K_NONE;
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return K_NONE;
    if (c == '\r' || c == '\n') return K_ENTER;
    if (c == '\t') return K_TAB;
    if (c == 9) return K_TAB;
    if (c == 27) {
        pollfd p2{ STDIN_FILENO, POLLIN, 0 };
        if (poll(&p2, 1, 5) <= 0) return K_ESC;
        unsigned char a, b;
        if (read(STDIN_FILENO, &a, 1) != 1) return K_ESC;
        if (a != '[' && a != 'O') return K_ESC;
        if (read(STDIN_FILENO, &b, 1) != 1) return K_ESC;
        switch (b) { case 'A': return K_UP; case 'B': return K_DOWN;
                     case 'C': return K_RIGHT; case 'D': return K_LEFT; }
        return K_NONE;
    }
    ch = (char)c; return K_CHAR;
}

static void openList(const char* file);

// Показать раздел в правой панели. Фокус НЕ трогаем — им управляет цикл ввода.
static void showScreen(int s) { g_screen = s; if (s == SCR_HOME) refreshHome(); g_dirty = true; }

// Проверка/обновление — отдельное действие, запускается только по Enter на разделе «Обновление».
static void updateAction() {
    if (g_updBusy) return;
    g_updBusy = true; g_updMsg = "Проверяю версию…"; g_dirty = true;
    std::thread([] {
        std::string rv = fetchRemoteVersion();
        if (rv.empty()) g_updMsg = "Не удалось получить версию с GitHub (сеть/прокси).";
        else if (rv == SCRIPT_VERSION) g_updMsg = "У тебя последняя версия (" + rv + ").";
        else {
            g_updMsg = "Есть версия " + rv + " — качаю и собираю…";
            g_dirty = true;
            bool ok = updateSelf();
            g_updMsg = ok ? ("Готово: обновлено до " + rv + ". Перезапусти Lag.")
                          : "Обновление не удалось — подробности в консоли после выхода.";
        }
        g_updBusy = false; g_dirty = true;
    }).detach();
}

int tuiMain() {
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "Lag TUI нужен настоящий терминал. Для скрипта: lag --run <раздел>.\n");
        return 2;
    }
    termSize(); termRaw();
    refreshHome();
    uint64_t lastClock = 0, lastHome = 0;
    bool run = true;
    while (run) {
        if (g_dirty.exchange(false)) render();
        char ch = 0; int k = readKey(ch);
        uint64_t now = GetTickCount64();
        if (now - lastClock > 30000) { lastClock = now; g_dirty = true; }        // часы раз в 30с
        if (g_screen == SCR_HOME && now - lastHome > 15000) { lastHome = now; refreshHome(); }
        if (g_busy) g_dirty = true;   // живой лог
        if (k == K_NONE) continue;

        if (k == K_CHAR && (ch == 'q' || ch == 'Q' || ch == '0')) { run = false; continue; }
        if (k == K_ESC) { showScreen(SCR_HOME); g_focus = 0; continue; }
        if (k == K_TAB) { if (g_screen != SCR_HOME) g_focus ^= 1; g_dirty = true; continue; }

        // Цифры 1-8: только ПЕРЕКЛЮЧАЮТ раздел, проверку НЕ запускают.
        if (k == K_CHAR && ch >= '1' && ch <= '8') {
            g_sel = ch - '1'; showScreen(g_sel); g_focus = 0; continue;
        }

        if (g_focus == 0) {   // фокус в меню: ↑↓ выбирают раздел и сразу показывают его (без запуска)
            if (k == K_UP)   { g_sel = (g_sel - 1 + SCR_COUNT) % SCR_COUNT; showScreen(g_sel); }
            if (k == K_DOWN) { g_sel = (g_sel + 1) % SCR_COUNT; showScreen(g_sel); }
            if (k == K_ENTER) {
                if (isRunnable(g_sel)) startRun(g_sel);        // запуск проверки — только по Enter
                else if (g_sel == SCR_UPDATE) updateAction();  // Обновление — проверить/обновить
                else g_focus = 1;                               // Настройки — войти в окно для правки
                g_dirty = true;
            }
            continue;
        }
        // фокус в окне
        if (g_screen == SCR_SETTINGS) {
            auto items = settingItems();
            if (k == K_UP)   g_setSel = (g_setSel - 1 + (int)items.size()) % items.size();
            if (k == K_DOWN) g_setSel = (g_setSel + 1) % items.size();
            if (k == K_LEFT || k == K_RIGHT) {
                SetItem& it = items[g_setSel];
                int v = *it.val + (k == K_RIGHT ? it.step : -it.step);
                if (v < it.lo) v = it.lo;
                if (v > it.hi) v = it.hi;
                *it.val = v;
            }
            if (k == K_CHAR && (ch == 's' || ch == 'S')) { saveConfig(); g_flash = "Сохранено в config.json"; }
            g_dirty = true; continue;
        }
        if (isRunnable(g_screen)) {
            int lh = g_rows - 5 - 4;
            if (k == K_UP)   { g_scroll[g_screen] = std::max(0, g_scroll[g_screen] - 1); g_follow = false; }
            if (k == K_DOWN) { g_scroll[g_screen] += 1; g_follow = false; }
            if (k == K_ENTER) startRun(g_screen);
            (void)lh; g_dirty = true; continue;
        }
        if (g_screen == SCR_UPDATE) { if (k == K_ENTER) updateAction(); g_dirty = true; continue; }
    }
    termRestore();
    return 0;
}

// ================== HEADLESS (--run) ==================
// Печатает лог раздела в обычную консоль с цветом — для cron и проверки.
static int headlessRun(const std::string& which) {
    int scr = -1;
    for (int i = SCR_SITES; i <= SCR_NET; i++)
        if (which == MENU[i].folderKey || which == std::string(MENU[i].name)) scr = i;
    if (which == "all") scr = -2;
    if (scr == -1) {
        fprintf(stderr, "Неизвестный раздел '%s'. Доступно: sites dns zond trace ports net (или all).\n", which.c_str());
        return 2;
    }
    auto one = [](int s) {
        g_guiSink = [](const std::string& c, const std::string& t) {
            printf("%s%s%s\n", logColor(c), t.c_str(), ui::RESET);
        };
        std::string lf = startReport(MENU[s].folderKey);
        switch (s) {
            case SCR_SITES: runSitesCheck(lf, loadItemList("sites.txt")); break;
            case SCR_DNS:   invokeWebAndDns(lf); break;
            case SCR_ZOND:  runBlockProbe(lf, loadItemList("sites.txt")); break;
            case SCR_PORTS: invokeServiceScan(lf, loadItemList("scan_targets.txt")); break;
            case SCR_NET:   invokeNetState(lf); break;
            case SCR_TRACE: { for (auto& t : loadItemList("trace_targets.txt")) analyzeTrace(t, lf); break; }
        }
        printf("%s\nОтчёт сохранён: %s%s\n", ui::DIM, lf.c_str(), ui::RESET);
        g_guiSink = nullptr;
    };
    if (scr == -2) { for (int i = SCR_SITES; i <= SCR_NET; i++) one(i); }
    else one(scr);
    return 0;
}

// "sites"/"dns"/... короткие псевдонимы -> folderKey
static std::string normSection(const std::string& a) {
    if (a == "sites") return "http";
    if (a == "dns")   return "dns_full";
    if (a == "zond" || a == "probe") return "block_probe";
    if (a == "ports") return "service_scan";
    if (a == "net" || a == "vpn") return "netstate";
    return a;
}
