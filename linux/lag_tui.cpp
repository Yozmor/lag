// lag_tui.cpp — терминальный интерфейс Lag для Linux по макету Windows-версии.
// Чистый ANSI + termios, без ncurses. 24-битный цвет (truecolor).
// Включается последним (lag.cpp подключает core, probe, tui).
//
// Поведение: ↑↓ в меню выбирают раздел и сразу показывают его (без запуска);
// проверка стартует только по Enter; 1-8 переключают раздел; Tab — фокус в окно
// (прокрутка лога / правка настроек); Esc — на главную; Q/0 — выход.
// Экраны разделов показывают вывод проверки построчно, как в Windows-версии.

#include <termios.h>
#include <sys/ioctl.h>
#include <poll.h>

// ---------- палитра (truecolor; каждый токен несёт тёмно-синий фон) ----------
#define BG "\033[48;2;14;28;46m"
#define FG(r,g,b) "\033[48;2;14;28;46;38;2;" #r ";" #g ";" #b "m"
namespace ui {
    const char* AMBER  = FG(232,163,61);
    const char* AMBERD = FG(156,116,48);
    const char* TEAL   = FG(82,180,194);
    const char* TEALD  = FG(47,111,120);
    const char* TX     = FG(205,214,220);
    const char* DIM    = FG(109,123,134);
    const char* GREEN  = FG(103,192,143);
    const char* RED    = FG(226,112,107);
    const char* MAG    = FG(201,139,208);
    // плашка подвала: янтарный фон, тёмный текст
    const char* CHIP   = "\033[48;2;232;163;61;38;2;14;28;46m";
}
static const char* logColor(const std::string& c) {
    if (c == "Red")     return ui::RED;
    if (c == "Green")   return ui::GREEN;
    if (c == "Yellow")  return ui::AMBER;
    if (c == "Cyan")    return ui::TEAL;
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
    { "ЗОНД",        "block_probe",  "тип блока: DNS / IP / SNI + NAT" },
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
static std::atomic<bool> g_follow{true};

static void logPush(int scr, const std::string& color, const std::string& text) {
    std::lock_guard<std::mutex> lk(g_logMx);
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

// Запуск раздела в рабочем потоке. Одна проверка за раз.
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

// ================== ТЕРМИНАЛ ==================
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
    printf("\x1b[?1049h\x1b[?25l");
    fflush(stdout);
}
static void termRestore() {
    printf("\x1b[0m\x1b[?25h\x1b[?1049l");
    fflush(stdout);
    tcsetattr(STDIN_FILENO, TCSANOW, &g_oldt);
}

// обрезка строки по видимой ширине (UTF-8)
static std::string clip(const std::string& s, int w) {
    if (w <= 0) return "";
    std::string out; int n = 0;
    for (size_t i = 0; i < s.size() && n < w;) {
        unsigned char c = (unsigned char)s[i];
        int len = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xE ? 3 : (c >> 3) == 0x1E ? 4 : 1;
        out.append(s, i, len); i += len; n++;
    }
    return out;
}
static void mv(int r, int c) { printf("\x1b[%d;%dH", r, c); }
static void put(int r, int c, const char* color, const std::string& text) {
    mv(r, c); fputs(color, stdout); fputs(text.c_str(), stdout);
}
// рамка со скруглёнными углами и заголовком на верхней грани
static void box(int r, int c, int w, int h, const std::string& title, const char* col) {
    if (w < 2 || h < 2) return;
    std::string top = "╭"; for (int i = 0; i < w - 2; i++) top += "─"; top += "╮";
    std::string bot = "╰"; for (int i = 0; i < w - 2; i++) bot += "─"; bot += "╯";
    put(r, c, col, top);
    for (int y = 1; y < h - 1; y++) { put(r + y, c, col, "│"); put(r + y, c + w - 1, col, "│"); }
    put(r + h - 1, c, col, bot);
    if (!title.empty()) put(r, c + 2, col, " " + title + " ");
}

static std::string nowClock() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[48];
    snprintf(b, sizeof(b), "%02d.%02d.%04d   %02d:%02d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
    return b;
}

// ---------- логотип: янтарный «парус» + бирюзовая волна с мачтой ----------
static void drawLogo() {
    put(1, 2, ui::AMBER, "◣");  put(1, 4, ui::TEAL, "•─●─•");
    put(2, 2, ui::AMBER, "◣");  put(2, 4, ui::TEAL, "∿∿∿∿∿");
}

// ================== СНИМОК ДЛЯ ГЛАВНОЙ ==================
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

// последние отчёты
struct RepRow { std::string when, scr, color, size; time_t t; };
static std::vector<RepRow> recentReports(int limit) {
    std::vector<RepRow> out;
    if (limit < 0) limit = 0;
    std::vector<std::string> stack{ g_logsDir };
    std::vector<std::pair<std::string, std::string>> files;
    while (!stack.empty()) {
        std::string d = stack.back(); stack.pop_back();
        DIR* dir = opendir(d.c_str()); if (!dir) continue;
        while (dirent* e = readdir(dir)) {
            std::string n = e->d_name; if (n == "." || n == "..") continue;
            std::string full = d + "/" + n;
            struct stat st; if (stat(full.c_str(), &st) != 0) continue;
            if (S_ISDIR(st.st_mode)) stack.push_back(full);
            else if (n.size() > 4 && n.substr(n.size() - 4) == ".txt")
                files.push_back({ full, d.substr(d.rfind('/') + 1) });
        }
        closedir(dir);
    }
    const char* COLS[SCR_COUNT] = { "Amber", "Magenta", "Red", "Cyan", "Green", "Green", "Dim", "Dim" };
    for (auto& f : files) {
        struct stat st; if (stat(f.first.c_str(), &st) != 0) continue;
        RepRow r; r.t = st.st_mtime; r.color = "Dim"; r.scr = f.second;
        for (int i = 0; i < SCR_COUNT; i++) if (MENU[i].folderKey == f.second) { r.scr = MENU[i].name; r.color = COLS[i]; break; }
        struct tm lt; localtime_r(&st.st_mtime, &lt);
        char b[32];
        time_t today = time(nullptr) - (time(nullptr) % 86400);
        if (st.st_mtime >= today) snprintf(b, sizeof(b), "сегодня %02d:%02d", lt.tm_hour, lt.tm_min);
        else snprintf(b, sizeof(b), "%02d.%02d %02d:%02d", lt.tm_mday, lt.tm_mon + 1, lt.tm_hour, lt.tm_min);
        r.when = b;
        r.size = std::to_string((st.st_size + 1023) / 1024) + " КБ";
        out.push_back(r);
    }
    std::sort(out.begin(), out.end(), [](const RepRow& a, const RepRow& b) { return a.t > b.t; });
    if ((int)out.size() > limit) out.resize(limit);
    return out;
}
static const char* colByName(const std::string& c) {
    if (c == "Amber")   return ui::AMBER;
    if (c == "Magenta") return ui::MAG;
    if (c == "Red")     return ui::RED;
    if (c == "Cyan")    return ui::TEAL;
    if (c == "Green")   return ui::GREEN;
    return ui::DIM;
}

static int g_sel = 0;
static int g_screen = SCR_HOME;
static int g_focus = 0;
static std::string g_flash;

static void drawHeader() {
    drawLogo();
    put(1, 10, ui::AMBER, "Lag");
    fputs(ui::TEAL, stdout); fputs("  ·  диагностика сети и VPN", stdout);
    put(2, 10, ui::DIM, "прокси · TUN · DNS · трассировка · порты");
    std::string clock = nowClock();
    put(1, g_cols - (int)clip(clock, 99).size() - 1, ui::DIM, clock);
    std::string who = isAdmin() ? "ROOT ●" : "ПОЛЬЗОВАТЕЛЬ ●";
    put(2, g_cols - (int)clip(who, 99).size() - 1, isAdmin() ? ui::GREEN : ui::DIM, who);
    std::string rule; for (int i = 0; i < g_cols - 2; i++) rule += "─";
    put(3, 2, ui::TEALD, rule);
    put(4, 2, ui::TEALD, rule);
}

static int MENU_X = 2, MENU_W = 24, CONT_X = 28;

static void drawMenu() {
    int top = 6, h = g_rows - top - 1;
    box(top, MENU_X, MENU_W, h, "МЕНЮ", g_focus == 0 ? ui::AMBER : ui::TEALD);
    int inner = h - 2;
    bool airy = (inner >= SCR_COUNT * 2 + 4);
    int step = airy ? 2 : 1;
    int y = top + 2;
    for (int i = 0; i < SCR_COUNT; i++) {
        if (i == SCR_SETTINGS && airy) y += 1;              // зазор перед «Настройки»
        bool cur = (g_sel == i);
        if (cur) put(y, MENU_X, ui::AMBER, "▌");             // янтарная полоска у выбранного
        put(y, MENU_X + 3, cur ? ui::AMBER : ui::AMBER, std::to_string(i + 1));
        put(y, MENU_X + 5, cur ? ui::TX : ui::DIM, MENU[i].name);
        y += step;
    }
    y += (airy ? 1 : 0);
    put(y, MENU_X + 3, ui::DIM, "0");
    put(y, MENU_X + 5, ui::DIM, "Выход");
    put(top + h - 2, MENU_X + 3, ui::DIM, "Tab · фокус");
}

static void drawFooter() {
    int y = g_rows;
    struct { const char* k; const char* l; } keys[] = {
        { "↑↓", "раздел" }, { "Enter", "запустить" }, { "1-8", "переключить" },
        { "Tab", "окно" }, { "Esc", "главная" }, { "Q", "выход" },
    };
    int x = 2;
    for (auto& e : keys) {
        mv(y, x); fputs(ui::CHIP, stdout); printf(" %s ", e.k);
        int kw = (int)clip(e.k, 99).size() + 2;
        put(y, x + kw + 1, ui::DIM, e.l);
        x += kw + 1 + (int)clip(e.l, 99).size() + 3;
        if (x > g_cols - 10) break;
    }
}

// ---------- карточка состояния ----------
static void card(int x, int y, int w, const std::string& title, const std::string& v1, const std::string& v2, const char* v1c) {
    box(y, x, w, 5, title, ui::TEALD);
    put(y + 2, x + 2, v1c, clip(v1, w - 4));
    put(y + 3, x + 2, ui::TEAL, clip(v2, w - 4));
}

static void drawHomeContent(int cx, int cw) {
    int top = 6, h = g_rows - top - 1;
    box(top, cx, cw, h, "СОСТОЯНИЕ", g_focus == 1 ? ui::AMBER : ui::TEALD);
    int bw = (cw - 6) / 3, by = top + 2;
    if (!g_home.have) {
        card(cx + 2, by, bw, "ПОДКЛЮЧЕНИЕ", "определяю…", "", ui::DIM);
        card(cx + 2 + (bw + 1), by, bw, "ВНЕШНИЙ IP", "…", "", ui::DIM);
        card(cx + 2 + 2 * (bw + 1), by, bw, "РЕЖИМ VPN", "…", "", ui::DIM);
    } else {
        card(cx + 2, by, bw, "ПОДКЛЮЧЕНИЕ", g_home.conn, g_home.speed, ui::TX);
        card(cx + 2 + (bw + 1), by, bw, "ВНЕШНИЙ IP", g_home.ip, g_home.geo, ui::TX);
        card(cx + 2 + 2 * (bw + 1), by, bw, "РЕЖИМ VPN", g_home.vpnMode,
             g_home.vpnAddr, g_home.vpnMode == "не найден" ? ui::AMBER : ui::TX);
    }
    int qy = by + 6;
    put(qy, cx + 2, ui::TEAL, "БЫСТРЫЙ ЗАПУСК");
    for (int i = 0; i < 6; i++) {
        int ry = qy + 1 + i;
        put(ry, cx + 2, ui::AMBERD, "▏");
        put(ry, cx + 4, ui::AMBER, std::to_string(i + 1));
        put(ry, cx + 6, ui::TX, padRight(MENU[i].name, 13));
        put(ry, cx + 21, ui::DIM, clip(MENU[i].hint, cw - 24));
    }
    int rty = qy + 8;
    if (rty + 2 < top + h - 1) {
        put(rty, cx + 2, ui::TEAL, "ПОСЛЕДНИЕ ОТЧЁТЫ");
        auto reps = recentReports(top + h - 2 - (rty + 1));
        if (reps.empty()) put(rty + 1, cx + 4, ui::DIM, "ещё нет — выбери раздел и нажми Enter");
        for (size_t i = 0; i < reps.size(); i++) {
            int ry = rty + 1 + (int)i;
            put(ry, cx + 4, ui::DIM, padRight(reps[i].when, 14));
            put(ry, cx + 19, colByName(reps[i].color), padRight(clip(reps[i].scr, 12), 13));
            put(ry, cx + 33, ui::DIM, clip(reps[i].size, cw - 36));
        }
    }
}

static void drawRunContent(int scr, int cx, int cw) {
    int top = 6, ch = g_rows - top - 1;
    const char* fcol = g_focus == 1 ? ui::AMBER : ui::TEALD;
    box(top, cx, cw, ch, std::string(MENU[scr].name) + "  //  " + MENU[scr].hint, fcol);
    bool running = g_busy && g_runScr == scr;
    if (running)      put(top + 1, cx + 2, ui::GREEN, "● идёт проверка…");
    else if (g_busy)  put(top + 1, cx + 2, ui::AMBER, "● занято: идёт другая проверка — дождись");
    else { put(top + 1, cx + 2, ui::AMBER, "▶ ЗАПУСТИТЬ"); put(top + 1, cx + 15, ui::DIM, "[Enter]"); }
    int ly = top + 3, lh = ch - 4, lw = cw - 4;
    std::lock_guard<std::mutex> lk(g_logMx);
    auto& L = g_log[scr];
    int total = (int)L.size();
    if (g_follow && running) g_scroll[scr] = std::max(0, total - lh);
    int start = std::min(g_scroll[scr], std::max(0, total - lh));
    if (start < 0) start = 0;
    for (int i = 0; i < lh; i++) {
        int idx = start + i;
        if (idx < total) put(ly + i, cx + 2, logColor(L[idx].color), clip(L[idx].text, lw));
    }
    if (total > lh) { put(ly, cx + cw - 3, ui::DIM, "▲"); put(ly + lh - 1, cx + cw - 3, ui::DIM, "▼"); }
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
    int top = 6, h = g_rows - top - 1;
    box(top, cx, cw, h, "НАСТРОЙКИ  //  ←→ менять · S сохранить", g_focus == 1 ? ui::AMBER : ui::TEALD);
    auto items = settingItems();
    for (size_t i = 0; i < items.size(); i++) {
        int y = top + 2 + (int)i * 2;
        bool cur = (g_focus == 1 && g_setSel == (int)i);
        if (cur) put(y, cx + 1, ui::AMBER, "▌");
        put(y, cx + 3, cur ? ui::TX : ui::DIM, padRight(items[i].name, 24));
        std::string val = std::string(cur ? "◂ " : "  ") + std::to_string(*items[i].val) +
                          (items[i].unit[0] ? std::string(" ") + items[i].unit : "") + (cur ? " ▸" : "");
        put(y, cx + 30, cur ? ui::AMBER : ui::TEAL, val);
    }
    put(top + h - 2, cx + 3, ui::DIM, "Значения действуют сразу; S — записать в config.json.");
}

// ---------- Обновление ----------
static std::atomic<bool> g_updBusy{false};
static std::string g_updMsg = "Нажми Enter — проверю версию на GitHub.";
static void drawUpdate(int cx, int cw) {
    int top = 6, h = g_rows - top - 1;
    box(top, cx, cw, h, "ОБНОВЛЕНИЕ", g_focus == 1 ? ui::AMBER : ui::TEALD);
    put(top + 2, cx + 3, ui::DIM, "Текущая версия:");
    put(top + 2, cx + 20, ui::TX, SCRIPT_VERSION);
    put(top + 4, cx + 3, ui::TX, clip(g_updMsg, cw - 6));
    if (g_updBusy) put(top + 6, cx + 3, ui::AMBER, "● работаю…");
    else { put(top + 6, cx + 3, ui::AMBER, "▶ Проверить / обновить"); put(top + 6, cx + 27, ui::DIM, "[Enter]"); }
}

static void paintBg() {
    fputs(BG, stdout);
    for (int r = 1; r <= g_rows; r++) { mv(r, 1); fputs("\x1b[K", stdout); }
}

static void render() {
    paintBg();
    if (g_rows < 20 || g_cols < 80) {
        put(1, 2, ui::AMBER, "Lag — увеличь окно терминала.");
        put(2, 2, ui::DIM, "Нужно минимум 80×20, сейчас " + std::to_string(g_cols) + "×" + std::to_string(g_rows) +
                           ". Для скриптов: lag --run <раздел>.");
        fflush(stdout); return;
    }
    drawHeader();
    drawMenu();
    int cw = g_cols - CONT_X - 1;
    if (g_screen == SCR_HOME)        drawHomeContent(CONT_X, cw);
    else if (isRunnable(g_screen))   drawRunContent(g_screen, CONT_X, cw);
    else if (g_screen == SCR_SETTINGS) drawSettings(CONT_X, cw);
    else if (g_screen == SCR_UPDATE) drawUpdate(CONT_X, cw);
    drawFooter();
    if (!g_flash.empty()) put(g_rows, g_cols / 2, ui::GREEN, g_flash);
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
    if (c == 27) {
        pollfd p2{ STDIN_FILENO, POLLIN, 0 };
        if (poll(&p2, 1, 5) <= 0) return K_ESC;
        unsigned char a, b;
        if (read(STDIN_FILENO, &a, 1) != 1) return K_ESC;
        if (a != '[' && a != 'O') return K_ESC;
        if (read(STDIN_FILENO, &b, 1) != 1) return K_ESC;
        switch (b) { case 'A': return K_UP; case 'B': return K_DOWN; case 'C': return K_RIGHT; case 'D': return K_LEFT; }
        return K_NONE;
    }
    ch = (char)c; return K_CHAR;
}

static void showScreen(int s) { g_screen = s; if (s == SCR_HOME) refreshHome(); g_dirty = true; }

static void updateAction() {
    if (g_updBusy) return;
    g_updBusy = true; g_updMsg = "Проверяю версию…"; g_dirty = true;
    std::thread([] {
        std::string rv = fetchRemoteVersion();
        if (rv.empty()) g_updMsg = "Не удалось получить версию с GitHub (сеть/прокси).";
        else if (rv == SCRIPT_VERSION) g_updMsg = "У тебя последняя версия (" + rv + ").";
        else {
            g_updMsg = "Есть версия " + rv + " — качаю и собираю…"; g_dirty = true;
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
        termSize();
        if (g_dirty.exchange(false)) render();
        char ch = 0; int k = readKey(ch);
        uint64_t now = GetTickCount64();
        if (now - lastClock > 30000) { lastClock = now; g_dirty = true; }
        if (g_screen == SCR_HOME && now - lastHome > 15000) { lastHome = now; refreshHome(); }
        if (g_busy) g_dirty = true;
        if (k == K_NONE) continue;
        g_flash.clear();

        if (k == K_CHAR && (ch == 'q' || ch == 'Q' || ch == '0')) { run = false; continue; }
        if (k == K_ESC) { showScreen(SCR_HOME); g_focus = 0; continue; }
        if (k == K_TAB) { if (g_screen != SCR_HOME) g_focus ^= 1; g_dirty = true; continue; }

        if (k == K_CHAR && ch >= '1' && ch <= '8') {            // переключить раздел, без запуска
            g_sel = ch - '1'; showScreen(g_sel); g_focus = 0; continue;
        }

        if (g_focus == 0) {                                      // фокус в меню
            if (k == K_UP)   { g_sel = (g_sel - 1 + SCR_COUNT) % SCR_COUNT; showScreen(g_sel); }
            if (k == K_DOWN) { g_sel = (g_sel + 1) % SCR_COUNT; showScreen(g_sel); }
            if (k == K_ENTER) {
                if (isRunnable(g_sel)) startRun(g_sel);
                else if (g_sel == SCR_UPDATE) updateAction();
                else g_focus = 1;
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
            if (k == K_CHAR && (ch == 's' || ch == 'S')) { saveConfig(); g_flash = "Сохранено"; }
            g_dirty = true; continue;
        }
        if (isRunnable(g_screen)) {
            if (k == K_UP)   { g_scroll[g_screen] = std::max(0, g_scroll[g_screen] - 1); g_follow = false; }
            if (k == K_DOWN) { g_scroll[g_screen] += 1; g_follow = false; }
            if (k == K_ENTER) startRun(g_screen);
            g_dirty = true; continue;
        }
        if (g_screen == SCR_UPDATE) { if (k == K_ENTER) updateAction(); g_dirty = true; continue; }
    }
    termRestore();
    return 0;
}

// ================== HEADLESS (--run) ==================
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
            printf("%s%s\033[0m\n", logColor(c), t.c_str());
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
        printf("\033[0m\nОтчёт сохранён: %s\n", lf.c_str());
        g_guiSink = nullptr;
    };
    if (scr == -2) { for (int i = SCR_SITES; i <= SCR_NET; i++) one(i); }
    else one(scr);
    return 0;
}

static std::string normSection(const std::string& a) {
    if (a == "sites") return "http";
    if (a == "dns")   return "dns_full";
    if (a == "zond" || a == "probe") return "block_probe";
    if (a == "ports") return "service_scan";
    if (a == "net" || a == "vpn") return "netstate";
    return a;
}
