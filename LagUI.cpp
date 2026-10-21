// LagUI.cpp — оконный интерфейс Лага на Direct2D.
// Включает ядро целиком (Lag.cpp): все проверки берутся как есть, окно их переиспользует.
// Точка входа — wWinMain. Консольный consoleMain() остаётся в ядре, но не используется.
#define LAG_GUI 1
#define UNICODE
#define _UNICODE
#include "Lag.cpp"

#include <d2d1.h>
#include <dwrite.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <algorithm>

#ifdef _MSC_VER
#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#endif

// ----- геометрия окна (как на макетах) -----
static const int WIN_W = 1120, WIN_H = 680;

// ----- палитра (в тонах иконки) -----
static D2D1_COLOR_F rgb(int r, int g, int b, float a = 1.0f) {
    return D2D1::ColorF(r / 255.0f, g / 255.0f, b / 255.0f, a);
}
namespace pal {
    const D2D1_COLOR_F BG    = rgb(6, 22, 36);
    const D2D1_COLOR_F PANEL = rgb(5, 20, 33, 0.60f);
    const D2D1_COLOR_F BOX   = rgb(8, 30, 46, 0.70f);    // фон плиток
    const D2D1_COLOR_F BOXLN = rgb(70, 200, 200, 0.25f); // рамка плиток
    const D2D1_COLOR_F AM    = rgb(240, 170, 60);    // янтарь
    const D2D1_COLOR_F AMD   = rgb(150, 105, 40);    // тёмный янтарь
    const D2D1_COLOR_F ICE   = rgb(70, 200, 200);    // бирюза
    const D2D1_COLOR_F TX    = rgb(226, 230, 235);   // основной текст
    const D2D1_COLOR_F STD   = rgb(120, 140, 160);   // приглушённый
    const D2D1_COLOR_F NAVTX = rgb(120, 150, 175);   // неактивные пункты
    const D2D1_COLOR_F GRID  = rgb(48, 176, 200, 0.07f);
    const D2D1_COLOR_F GN    = rgb(80, 215, 140);
    const D2D1_COLOR_F RED   = rgb(235, 80, 90);
    const D2D1_COLOR_F YEL   = rgb(235, 200, 90);
    const D2D1_COLOR_F NAVON = rgb(40, 30, 10);      // фон активного пункта меню
    const D2D1_COLOR_F SEL   = rgb(240, 170, 60, 0.12f); // подсветка выбранной строки
    const D2D1_COLOR_F DARK  = rgb(25, 15, 0);       // текст на янтарной кнопке
}
// цвет строки лога по имени (как в консоли)
static D2D1_COLOR_F colorFor(const std::string& c) {
    if (c == "Green")   return pal::GN;
    if (c == "Red")     return pal::RED;
    if (c == "Yellow")  return pal::YEL;
    if (c == "Cyan")    return pal::ICE;
    if (c == "Magenta") return pal::AM;
    if (c == "Gray")    return pal::STD;
    return pal::TX;
}

// ----- пункты меню -----
enum Screen { SCR_HOME, SCR_SITES, SCR_DNS, SCR_TRACE, SCR_PORTS, SCR_NET, SCR_REPORTS, SCR_LISTS, SCR_SETTINGS, SCR_COUNT };
static const wchar_t* NAV[SCR_COUNT] = {
    L"ГЛАВНАЯ", L"САЙТЫ", L"DNS", L"ТРАССА", L"ПОРТЫ", L"СЕТЬ / VPN", L"ОТЧЁТЫ", L"СПИСКИ", L"НАСТРОЙКИ"
};
static std::string NAV_u8(int i) { return toU8(NAV[i]); }

// ----- глобальное состояние окна -----
struct UI {
    HWND hwnd = nullptr;
    ID2D1Factory*          d2d = nullptr;
    IDWriteFactory*        dw  = nullptr;
    ID2D1HwndRenderTarget* rt  = nullptr;
    IDWriteTextFormat* fRegular = nullptr;   // моноширинный 14
    IDWriteTextFormat* fBold    = nullptr;   // моноширинный 14 жирный
    IDWriteTextFormat* fSmall   = nullptr;   // 11 — подписи
    IDWriteTextFormat* fTiny    = nullptr;   // 10 — заголовки плиток
    IDWriteTextFormat* fMid     = nullptr;   // 12 — списки и просмотр отчёта
    IDWriteTextFormat* fBig     = nullptr;   // 18 жирный — значения в плитках
    IDWriteTextFormat* fTitle   = nullptr;   // 26 — «ЛАГ»
    int screen = SCR_HOME;
    bool admin = false;
    int mouseX = 0, mouseY = 0;              // последняя позиция мыши (для ползунков)
};
static UI g;

template <class T> static void safeRelease(T*& p) { if (p) { p->Release(); p = nullptr; } }

// фоновые потоки (обновление состояния, проверка версии) — чтобы корректно выйти
static std::atomic<int>  g_bg{0};
static std::atomic<bool> g_dirty{false};   // «надо перерисовать» — выставляют фоновые потоки

// ----- шрифты -----
static IDWriteTextFormat* makeFont(float size, bool bold, const wchar_t* family = L"Consolas") {
    IDWriteTextFormat* f = nullptr;
    g.dw->CreateTextFormat(family, nullptr,
        bold ? DWRITE_FONT_WEIGHT_BOLD : DWRITE_FONT_WEIGHT_NORMAL,
        DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, size, L"ru-RU", &f);
    if (f) f->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);   // длинные строки обрезаем, не переносим
    return f;
}
static void createDeviceIndependent() {
    D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &g.d2d);
    DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown**)&g.dw);
    g.fRegular = makeFont(14.0f, false);
    g.fBold    = makeFont(14.0f, true);
    g.fSmall   = makeFont(11.0f, false);
    g.fTiny    = makeFont(10.0f, false);
    g.fMid     = makeFont(12.0f, false);
    g.fBig     = makeFont(18.0f, true);
    g.fTitle   = makeFont(26.0f, true);
}
static void discardDeviceIndependent() {
    safeRelease(g.fRegular); safeRelease(g.fBold); safeRelease(g.fSmall); safeRelease(g.fTiny);
    safeRelease(g.fMid); safeRelease(g.fBig); safeRelease(g.fTitle);
    safeRelease(g.dw); safeRelease(g.d2d);
}
static void ensureRenderTarget() {
    if (g.rt) return;
    RECT rc; GetClientRect(g.hwnd, &rc);
    g.d2d->CreateHwndRenderTarget(
        D2D1::RenderTargetProperties(),
        D2D1::HwndRenderTargetProperties(g.hwnd, D2D1::SizeU(rc.right - rc.left, rc.bottom - rc.top)),
        &g.rt);
}

// ----- примитивы рисования -----
static ID2D1SolidColorBrush* g_brush = nullptr;  // переиспользуемая кисть
static void setColor(const D2D1_COLOR_F& c) { if (g_brush) g_brush->SetColor(c); }
static void textW(const std::wstring& ws, float x, float y, IDWriteTextFormat* fmt, const D2D1_COLOR_F& col,
                  float w = 2000, float h = 40) {
    setColor(col);
    g.rt->DrawText(ws.c_str(), (UINT32)ws.size(), fmt,
                    D2D1::RectF(x, y, x + w, y + h), g_brush, D2D1_DRAW_TEXT_OPTIONS_CLIP);
}
static void text(const std::string& s, float x, float y, IDWriteTextFormat* fmt, const D2D1_COLOR_F& col,
                 float w = 2000, float h = 40) {
    textW(toW(s), x, y, fmt, col, w, h);
}
// ширина текста в пикселях (для центрирования и выравнивания по правому краю)
static float textWidth(const std::wstring& s, IDWriteTextFormat* f) {
    IDWriteTextLayout* L = nullptr;
    if (FAILED(g.dw->CreateTextLayout(s.c_str(), (UINT32)s.size(), f, 4000.0f, 200.0f, &L)) || !L)
        return s.size() * 8.0f;
    DWRITE_TEXT_METRICS m{}; L->GetMetrics(&m); L->Release();
    return m.widthIncludingTrailingWhitespace;
}
static void line(float x0, float y0, float x1, float y1, const D2D1_COLOR_F& col, float wd = 1.0f) {
    setColor(col);
    g.rt->DrawLine(D2D1::Point2F(x0, y0), D2D1::Point2F(x1, y1), g_brush, wd);
}
static void rectFill(float x0, float y0, float x1, float y1, const D2D1_COLOR_F& col) {
    setColor(col);
    g.rt->FillRectangle(D2D1::RectF(x0, y0, x1, y1), g_brush);
}
static void rectLine(float x0, float y0, float x1, float y1, const D2D1_COLOR_F& col, float wd = 1.0f) {
    setColor(col);
    g.rt->DrawRectangle(D2D1::RectF(x0 + 0.5f, y0 + 0.5f, x1 - 0.5f, y1 - 0.5f), g_brush, wd);
}
// плитка: полупрозрачный фон + тонкая рамка
static void box(float x, float y, float w, float h, const D2D1_COLOR_F& border = pal::BOXLN,
                const D2D1_COLOR_F& fill = pal::BOX) {
    rectFill(x, y, x + w, y + h, fill);
    rectLine(x, y, x + w, y + h, border);
}
// уголки-скобки, как на макетах
static void bracket(float x, float y, int dir, const D2D1_COLOR_F& col) {
    const float L = 16;
    float hx = (dir & 1) ? -L : L;   // 1 = правый
    float vy = (dir & 2) ? -L : L;   // 2 = нижний
    line(x, y, x + hx, y, col);
    line(x, y, x, y + vy, col);
}

// ===================== КЛИКАБЕЛЬНЫЕ ОБЛАСТИ =====================
// Каждый кадр экран заново «регистрирует» свои кнопки: прямоугольник + что делать по клику.
// Так не нужно отдельно хранить координаты каждой кнопки для обработчика мыши.
struct Hit { D2D1_RECT_F r; std::function<void()> fn; };
static std::vector<Hit> g_hits;
static void addHit(float x0, float y0, float x1, float y1, std::function<void()> fn) {
    g_hits.push_back({ D2D1::RectF(x0, y0, x1, y1), std::move(fn) });
}
// стили кнопок: 0 — главная (янтарная), 1 — вторичная, 2 — опасная, 3 — неактивная
enum BtnStyle { BTN_MAIN, BTN_SEC, BTN_DANGER, BTN_OFF };
static void button(float x, float y, float w, float h, const std::wstring& label, int style,
                   std::function<void()> fn = nullptr) {
    D2D1_COLOR_F fill = pal::NAVON, border = pal::AMD, tx = pal::AM;
    IDWriteTextFormat* f = g.fRegular;
    if (style == BTN_MAIN)   { fill = pal::AM; border = rgb(255, 210, 120); tx = pal::DARK; f = g.fBold; }
    if (style == BTN_DANGER) { border = rgb(235, 80, 90, 0.5f); tx = pal::RED; }
    if (style == BTN_OFF)    { tx = pal::STD; }
    rectFill(x, y, x + w, y + h, fill);
    rectLine(x, y, x + w, y + h, border);
    float tw = textWidth(label, f);
    textW(label, x + (w - tw) / 2.0f, y + (h - 17.0f) / 2.0f, f, tx, w, h);
    if (fn && style != BTN_OFF) addHit(x, y, x + w, y + h, std::move(fn));
}

// ----- фон «пространство» -----
static void drawBackground() {
    rectFill(0, 0, (float)WIN_W, (float)WIN_H, pal::BG);
    for (int x = 0; x < WIN_W; x += 40) line((float)x, 0, (float)x, (float)WIN_H, pal::GRID);
    for (int y = 0; y < WIN_H; y += 40) line(0, (float)y, (float)WIN_W, (float)y, pal::GRID);
    // волны внизу
    for (int k = 0; k < 3; k++) {
        float yy = WIN_H - 96.0f + k * 32;
        float a = 0.16f + k * 0.08f;
        float px = -28, py = yy + 14;
        for (int x = -28; x < WIN_W + 56; x += 28) {
            float ny = yy + (((x / 28) & 1) ? 14.0f : -14.0f);
            line(px, py, (float)x, ny, rgb(48, 176, 200, a), 2.0f);
            px = (float)x; py = ny;
        }
    }
}

// ----- шапка -----
static std::wstring nowClock() {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t b[64];
    swprintf(b, 64, L"%02d.%02d.%04d   %02d:%02d", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute);
    return b;
}
static void drawHeader() {
    textW(L"ЛАГ", 26, 14, g.fTitle, pal::AM);
    text(std::string("//  v") + SCRIPT_VERSION + "  ·  диагностика сети и VPN", 150, 26, g.fRegular, pal::ICE);
    textW(nowClock(), WIN_W - 230.0f, 20, g.fRegular, pal::TX, 210);
    std::wstring role = g.admin ? L"АДМИНИСТРАТОР ●" : L"ПОЛЬЗОВАТЕЛЬ ○";
    textW(role, WIN_W - 230.0f, 40, g.fSmall, g.admin ? pal::GN : pal::STD, 210);
    line(26, 70, WIN_W - 26.0f, 70, pal::AMD, 1.0f);
}

// ----- футер -----
static void drawFooter(const std::wstring& hint) {
    line(26, WIN_H - 58.0f, WIN_W - 26.0f, WIN_H - 58.0f, pal::GRID);
    textW(hint, 26, WIN_H - 46.0f, g.fRegular, pal::AM, WIN_W - 52.0f);
}

// область панели (как в каркасе)
static const float LPX = 236, LPY = 98, LPW = WIN_W - 24 - 236, LPH = WIN_H - 84 - 98;
static float X(float x) { return LPX + x; }   // координаты внутри панели → координаты окна
static float Y(float y) { return LPY + y; }

static void setScreen(int s);                 // переключение раздела (определена ниже)
static void openReport(const std::wstring& p); // открыть отчёт в разделе ОТЧЁТЫ (ниже)

// ===================== ЖИВОЙ ВЫВОД ПРОВЕРОК =====================
// У каждого раздела свой лог: переключился на другой пункт — видишь только его вывод,
// вернулся — снова видишь свой. Разделы можно запускать параллельно, каждый в своём потоке.
struct LogLine { D2D1_COLOR_F col; std::wstring text; };
struct ScreenLog {
    std::vector<LogLine> lines;
    float scroll = 0;       // прокрутка (в строках)
    bool  follow = true;    // держаться конца при поступлении строк
};
static std::mutex g_logMx;
static ScreenLog g_logs[SCR_COUNT];
static std::atomic<bool> g_busy[SCR_COUNT];      // какие разделы сейчас выполняются
static std::atomic<bool> g_reportsDirty{true};   // появился новый отчёт — пересканировать Logs
static const float ROWH = 18.0f;                 // высота строки лога

static bool screenBusy(int i) { return g_busy[i].load(); }
static bool anyBusy() {
    for (int i = 0; i < SCR_COUNT; i++) if (g_busy[i]) return true;
    return false;
}

// область лога внутри панели
static const float LOGX = LPX + 14, LOGY = LPY + 70, LOGW = LPW - 28, LOGH = LPH - 70 - 14;

static bool screenRunnable(int s) {
    return s == SCR_SITES || s == SCR_DNS || s == SCR_TRACE || s == SCR_PORTS || s == SCR_NET;
}
static const char* folderKeyFor(int s) {
    switch (s) {
        case SCR_SITES: return "http";
        case SCR_DNS:   return "dns_full";
        case SCR_TRACE: return "trace";
        case SCR_PORTS: return "service_scan";
        case SCR_NET:   return "netstate";
        default:        return "misc";
    }
}
// обратное: папка отчёта → раздел (-1, если неизвестная папка)
static int screenForKey(const std::string& k) {
    for (int s = SCR_SITES; s <= SCR_NET; s++) if (k == folderKeyFor(s)) return s;
    return -1;
}
// короткое имя раздела для таблиц
static std::wstring shortName(int s) {
    switch (s) {
        case SCR_SITES: return L"САЙТЫ";
        case SCR_DNS:   return L"DNS";
        case SCR_TRACE: return L"ТРАССА";
        case SCR_PORTS: return L"ПОРТЫ";
        case SCR_NET:   return L"СЕТЬ";
        default:        return L"?";
    }
}

// выполняется в рабочем потоке — ни одного обращения к Direct2D отсюда
static void runWorker(int screen) {
    // строки уходят в лог именно того раздела, который запустили
    g_guiSink = [screen](const std::string& color, const std::string& t) {
        // ядро иногда шлёт строку с '\n' внутри ("\n--- ЗАГОЛОВОК ---") — режем на отдельные строки
        std::lock_guard<std::mutex> lk(g_logMx);
        auto& dst = g_logs[screen].lines;
        D2D1_COLOR_F c = colorFor(color);
        size_t a = 0;
        while (true) {
            size_t b = t.find('\n', a);
            std::string part = t.substr(a, b == std::string::npos ? std::string::npos : b - a);
            if (!part.empty() && part.back() == '\r') part.pop_back();
            dst.push_back({ c, toW(part) });
            if (b == std::string::npos) break;
            a = b + 1;
        }
        g_dirty = true;
    };
    std::wstring lf = startReport(folderKeyFor(screen));   // пишет и в файл, и в окно (через sink)
    switch (screen) {
        case SCR_SITES: invokeWebCheck(lf); break;
        case SCR_DNS:   invokeWebAndDns(lf); break;
        case SCR_PORTS: invokeServiceScan(lf, loadItemList(L"scan_targets.txt")); break;
        case SCR_NET:   invokeNetState(lf); break;
        case SCR_TRACE: {
            if (!isAdmin()) { writeLog("Для TCP-трассировки нужны права администратора.", "Red", lf); break; }
            auto tg = loadItemList(L"trace_targets.txt");
            if (tg.empty()) writeLog("Список trace_targets.txt пуст.", "Yellow", lf);
            for (auto& t : tg) analyzeTrace(t, lf);
            break;
        }
    }
    writeLog("", "Gray", lf);
    writeLog("Отчёт сохранён: " + toU8(lf), "Cyan", lf);
    g_guiSink = nullptr;
    g_busy[screen] = false;
    g_reportsDirty = true;   // главная и «Отчёты» подхватят новый файл
    g_dirty = true;
}
static void startRun(int screen) {
    if (!screenRunnable(screen) || g_busy[screen]) return;   // этот раздел уже идёт
    {
        std::lock_guard<std::mutex> lk(g_logMx);
        g_logs[screen] = ScreenLog{};   // старый вывод этого раздела стираем, другие не трогаем
    }
    g_busy[screen] = true; g_dirty = true;
    std::thread(runWorker, screen).detach();
}
static size_t logCount(int s) { std::lock_guard<std::mutex> lk(g_logMx); return g_logs[s].lines.size(); }

// кнопка «Запустить» / индикатор
static void drawRunBar() {
    float x0 = LPX + 14, y0 = LPY + 30;
    bool busy = g_busy[g.screen].load();
    if (busy) button(x0, y0, 220, 32, L"ИДЁТ ПРОВЕРКА…", BTN_OFF);
    else      button(x0, y0, 220, 32, L"ЗАПУСТИТЬ  [Enter]", BTN_MAIN, [] { startRun(g.screen); });
    // справа: счётчик строк + сколько разделов идёт параллельно
    int running = 0; for (int i = 0; i < SCR_COUNT; i++) if (g_busy[i]) running++;
    std::string info = "строк: " + std::to_string(logCount(g.screen));
    if (running > 1) info += "   ·   параллельно идут проверок: " + std::to_string(running);
    text(info, x0 + 240, y0 + 8, g.fRegular, pal::STD);
}

static void drawLog() {
    rectLine(LOGX - 2, LOGY - 2, LOGX + LOGW + 2, LOGY + LOGH + 2, pal::GRID);
    int visible = (int)(LOGH / ROWH);
    std::lock_guard<std::mutex> lk(g_logMx);
    ScreenLog& S = g_logs[g.screen];
    int total = (int)S.lines.size();
    if (total == 0) {
        text("Здесь появится вывод проверки. Нажми «Запустить» или Enter.",
             LOGX + 4, LOGY + 4, g.fRegular, pal::STD);
        return;
    }
    int maxScroll = total > visible ? total - visible : 0;
    if (S.follow) S.scroll = (float)maxScroll;
    if (S.scroll < 0) S.scroll = 0;
    if (S.scroll > maxScroll) S.scroll = (float)maxScroll;
    if (!S.follow && S.scroll >= maxScroll) S.follow = true;   // докрутил до низа — снова следим за концом
    int first = (int)S.scroll;
    g.rt->PushAxisAlignedClip(D2D1::RectF(LOGX, LOGY, LOGX + LOGW, LOGY + LOGH), D2D1_ANTIALIAS_MODE_ALIASED);
    float y = LOGY;
    for (int i = first; i < total && y < LOGY + LOGH; i++, y += ROWH) {
        const LogLine& L = S.lines[i];
        textW(L.text, LOGX, y, g.fRegular, L.col, LOGW, ROWH);
    }
    g.rt->PopAxisAlignedClip();
    if (total > visible) {   // полоса прокрутки
        float thumbH = LOGH * visible / total;
        float thumbY = LOGY + LOGH * (S.scroll / total);
        rectFill(LOGX + LOGW + 4, LOGY, LOGX + LOGW + 8, LOGY + LOGH, rgb(20, 40, 55));
        rectFill(LOGX + LOGW + 4, thumbY, LOGX + LOGW + 8, thumbY + thumbH, pal::AMD);
    }
}

static void drawRunScreen() {
    static const char* SUB[SCR_COUNT] = {
        "", "доступность: напрямую и через VPN", "HTTP + все DNS, сравнение IP",
        "TCP-трассировка (nexttrace)", "сканирование портов, баннеры, CVE",
        "IP, порты прокси, маршруты, утечки", "", ""
    };
    text(NAV_u8(g.screen) + "  //  " + SUB[g.screen], X(4), Y(2), g.fRegular, pal::AM);
    drawRunBar();
    drawLog();
}

// ===================== ОТЧЁТЫ НА ДИСКЕ =====================
// Структура: Logs\<подключение>\<раздел>\ГГГГ-ММ-ДД_ЧЧММСС.txt
struct ReportFile {
    std::wstring path;
    std::wstring name;       // имя файла
    std::string  conn;       // папка подключения (UTF-8)
    int screen = -1;         // раздел (SCR_SITES…SCR_NET) или -1
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    ULONGLONG size = 0;
};
static std::vector<ReportFile> g_reports;   // отсортированы: новые сверху

struct Summary { std::wstring text; D2D1_COLOR_F col; };
static Summary g_lastSum[SCR_COUNT];        // итог последнего отчёта каждого раздела

// прочитать текстовый файл построчно (UTF-8)
static std::vector<std::string> readLines(const std::wstring& path, size_t maxLines = 5000) {
    std::vector<std::string> out;
    std::ifstream f(path, std::ios::binary);
    std::string ln;
    while (out.size() < maxLines && std::getline(f, ln)) {
        if (!ln.empty() && ln.back() == '\r') ln.pop_back();
        out.push_back(ln);
    }
    return out;
}
static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// «сегодня 09:24» / «вчера 22:10» / «18.10 14:02»
static long dayNumber(int y, int mo, int d) {
    SYSTEMTIME st{}; st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDay = (WORD)d;
    FILETIME ft; if (!SystemTimeToFileTime(&st, &ft)) return 0;
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return (long)(u.QuadPart / 864000000000ULL);
}
static std::wstring whenStr(const ReportFile& r, bool words = true) {
    wchar_t b[64];
    SYSTEMTIME now; GetLocalTime(&now);
    long diff = dayNumber(now.wYear, now.wMonth, now.wDay) - dayNumber(r.y, r.mo, r.d);
    if (words && diff == 0)      swprintf(b, 64, L"сегодня %02d:%02d", r.h, r.mi);
    else if (words && diff == 1) swprintf(b, 64, L"вчера %02d:%02d", r.h, r.mi);
    else                         swprintf(b, 64, L"%02d.%02d %02d:%02d", r.d, r.mo, r.h, r.mi);
    return b;
}
static std::wstring sizeStr(ULONGLONG sz) {
    return std::to_wstring((sz + 1023) / 1024) + L" КБ";
}

// краткий итог отчёта для плитки на главной
static Summary summarize(int screen, const ReportFile& rf) {
    auto lines = readLines(rf.path);
    if (screen == SCR_SITES) {
        int ok = 0, total = 0;
        for (auto& l : lines) {
            if (!has(l, " | ")) continue;                   // строки таблицы содержат « | »
            std::vector<std::string> cells; size_t a = 0, b;
            while ((b = l.find(" | ", a)) != std::string::npos) { cells.push_back(trim(l.substr(a, b - a))); a = b + 3; }
            cells.push_back(trim(l.substr(a)));
            if (cells.empty() || cells[0] == "Сайт") continue;   // заголовок таблицы
            total++;
            if (cells.back() != "timeout") ok++;             // последняя колонка: через VPN / через туннель
        }
        if (total == 0) return { L"прошлый: нет данных", pal::STD };
        D2D1_COLOR_F c = ok == total ? pal::GN : (ok == 0 ? pal::RED : pal::YEL);
        return { L"прошлый: " + std::to_wstring(ok) + L"/" + std::to_wstring(total) + L" доступны", c };
    }
    if (screen == SCR_PORTS) {
        int cve = 0;
        for (auto& l : lines) if (has(l, "CVE-")) cve++;
        if (cve) return { L"прошлый: CVE — " + std::to_wstring(cve), pal::YEL };
        return { L"прошлый: уязвимостей нет", pal::GN };
    }
    if (screen == SCR_NET) {
        bool leak = false, prob = false;
        for (auto& l : lines) { if (has(l, "УТЕЧКА")) leak = true; if (has(l, "[ПРОБЛЕМА]")) prob = true; }
        if (leak) return { L"прошлый: утечка маршрута", pal::RED };
        if (prob) return { L"прошлый: есть проблемы", pal::RED };
        return { L"прошлый: без проблем", pal::GN };
    }
    return { L"прошлый: " + whenStr(rf), pal::STD };    // DNS и трасса — только время
}

// обойти Logs и собрать список отчётов (быстро: только имена и размеры)
static void scanReports() {
    g_reports.clear();
    WIN32_FIND_DATAW fd;
    HANDLE h1 = FindFirstFileW((g_logsDir + L"\\*").c_str(), &fd);
    if (h1 != INVALID_HANDLE_VALUE) {
        do {
            std::wstring conn = fd.cFileName;
            if (conn == L"." || conn == L".." || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            std::wstring connDir = g_logsDir + L"\\" + conn;
            WIN32_FIND_DATAW fd2;
            HANDLE h2 = FindFirstFileW((connDir + L"\\*").c_str(), &fd2);
            if (h2 == INVALID_HANDLE_VALUE) continue;
            do {
                std::wstring key = fd2.cFileName;
                if (key == L"." || key == L".." || !(fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                std::wstring keyDir = connDir + L"\\" + key;
                WIN32_FIND_DATAW fd3;
                HANDLE h3 = FindFirstFileW((keyDir + L"\\*.txt").c_str(), &fd3);
                if (h3 == INVALID_HANDLE_VALUE) continue;
                do {
                    if (fd3.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    ReportFile r;
                    r.name = fd3.cFileName;
                    r.path = keyDir + L"\\" + r.name;
                    r.conn = toU8(conn);
                    r.screen = screenForKey(toU8(key));
                    r.size = ((ULONGLONG)fd3.nFileSizeHigh << 32) | fd3.nFileSizeLow;
                    if (swscanf(r.name.c_str(), L"%4d-%2d-%2d_%2d%2d%2d",
                                &r.y, &r.mo, &r.d, &r.h, &r.mi, &r.s) != 6) {
                        // имя не по шаблону — берём время изменения файла
                        FILETIME lt; SYSTEMTIME st;
                        FileTimeToLocalFileTime(&fd3.ftLastWriteTime, &lt); FileTimeToSystemTime(&lt, &st);
                        r.y = st.wYear; r.mo = st.wMonth; r.d = st.wDay; r.h = st.wHour; r.mi = st.wMinute; r.s = st.wSecond;
                    }
                    g_reports.push_back(r);
                } while (FindNextFileW(h3, &fd3));
                FindClose(h3);
            } while (FindNextFileW(h2, &fd2));
            FindClose(h2);
        } while (FindNextFileW(h1, &fd));
        FindClose(h1);
    }
    auto stamp = [](const ReportFile& r) {
        return ((((long long)r.y * 100 + r.mo) * 100 + r.d) * 100 + r.h) * 10000LL + r.mi * 100 + r.s;
    };
    std::sort(g_reports.begin(), g_reports.end(),
              [&](const ReportFile& a, const ReportFile& b) { return stamp(a) > stamp(b); });
    // итоги для плиток: самый свежий отчёт каждого раздела
    for (int s = 0; s < SCR_COUNT; s++) g_lastSum[s] = { L"ещё не запускался", pal::STD };
    bool done[SCR_COUNT] = {};
    for (auto& r : g_reports) {
        if (r.screen < 0 || done[r.screen]) continue;
        g_lastSum[r.screen] = summarize(r.screen, r);
        done[r.screen] = true;
    }
}

// ===================== ГЛАВНАЯ: СОСТОЯНИЕ СЕТИ =====================
struct HomeStatus {
    bool have = false;                 // данные уже есть
    std::string connType, connDetail, linkSpeed, tunName;
    bool tunUp = false;                // поднят туннельный адаптер (например, Yggdrasil)
    VpnMode mode = VpnMode::None;
    std::string proxy;                 // как в реестре, напр. 127.0.0.1:10809
    int httpPort = 0, socksPort = 0;
    GeoInfo exitg, real;               // IP выхода и реальный IP (последний — только в прокси-режиме)
    std::wstring updated;              // «09:31:12»
};
static std::mutex g_stMx;
static HomeStatus g_st;
static std::atomic<bool> g_stLoading{false};
static ULONGLONG g_stTick = 0;         // когда последний раз запускали обновление

static void refreshStatus() {
    if (g_stLoading.exchange(true)) return;   // уже обновляется
    g_stTick = GetTickCount64();
    g_bg++; g_dirty = true;
    std::thread([] {
        HomeStatus s;
        ConnInfo ci = getConnectionType();
        s.connType = ci.BaseType; s.connDetail = ci.Detail; s.linkSpeed = ci.LinkSpeed;
        s.tunUp = ci.VpnActive; s.tunName = ci.VpnName;
        std::wstring proxyW;
        s.mode = detectVpnMode(proxyW);
        s.proxy = toU8(proxyW);
        std::string host;
        if (!proxyW.empty() && parseProxyAddr(proxyW, host, s.httpPort))
            s.socksPort = g_config.SocksPort > 0 ? g_config.SocksPort : s.httpPort - 1;
        if (s.mode == VpnMode::Proxy) {
            s.exitg = fetchGeo(true, proxyW);    // через прокси — IP VPN-сервера
            s.real  = fetchGeo(false, L"");      // напрямую — реальный IP
        } else {
            s.exitg = fetchGeo(false, L"");
        }
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t b[32]; swprintf(b, 32, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        s.updated = b;
        s.have = true;
        { std::lock_guard<std::mutex> lk(g_stMx); g_st = s; }
        g_stLoading = false;
        g_bg--; g_dirty = true;
    }).detach();
}

static std::wstring W(const std::string& s) { return toW(s); }

static void drawHome() {
    textW(L"ГЛАВНАЯ  //  состояние сейчас", X(4), Y(2), g.fRegular, pal::AM);
    HomeStatus s; { std::lock_guard<std::mutex> lk(g_stMx); s = g_st; }
    bool loading = g_stLoading.load();
    std::wstring upd = loading ? L"обновляю…   " : (s.have ? L"обновлено " + s.updated + L"   " : L"");
    std::wstring updFull = upd + L"[F5] ↻";
    float uw = textWidth(updFull, g.fSmall);
    textW(upd, X(LPW - 14) - uw, Y(4), g.fSmall, pal::STD);
    textW(L"[F5] ↻", X(LPW - 14) - textWidth(L"[F5] ↻", g.fSmall), Y(4), g.fSmall, pal::AM);
    addHit(X(LPW - 14) - uw, Y(2), X(LPW - 14), Y(20), [] { refreshStatus(); });

    const float ty = 30, th = 96;
    // --- плитка «Подключение» ---
    box(X(14), Y(ty), 270, th);
    textW(L"ПОДКЛЮЧЕНИЕ", X(26), Y(ty + 10), g.fTiny, pal::STD);
    if (!s.have) textW(L"…", X(26), Y(ty + 28), g.fBig, pal::STD);
    else {
        bool none = s.connType == "Неизвестно";
        textW(none ? L"○" : L"●", X(26), Y(ty + 27), g.fBig, none ? pal::RED : pal::GN);
        textW(W(none ? "нет сети" : s.connType), X(48), Y(ty + 27), g.fBig, pal::TX, 230);
        std::string d1 = (s.connDetail.empty() || s.connDetail == "-") ? "" : "«" + s.connDetail + "»";
        if (!s.linkSpeed.empty()) d1 += (d1.empty() ? "" : " · ") + s.linkSpeed;
        text(d1, X(26), Y(ty + 54), g.fSmall, pal::STD, 250);
        if (s.tunUp && s.mode != VpnMode::Tun)
            text("+ туннель " + s.tunName + " (не считается за VPN)", X(26), Y(ty + 72), g.fSmall, pal::STD, 250);
    }
    // --- плитка «Внешний IP» ---
    box(X(296), Y(ty), 270, th);
    textW(L"ВНЕШНИЙ IP", X(308), Y(ty + 10), g.fTiny, pal::STD);
    if (!s.have) textW(L"…", X(308), Y(ty + 28), g.fBig, pal::STD);
    else if (s.exitg.ip.empty()) {
        textW(L"нет ответа", X(308), Y(ty + 27), g.fBig, pal::RED);
        text(s.mode == VpnMode::Proxy ? "через прокси IP не получить — прокси не пропускает трафик"
                                      : "сервис определения IP недоступен",
             X(308), Y(ty + 54), g.fSmall, pal::STD, 250);
    } else {
        textW(W(s.exitg.ip), X(308), Y(ty + 27), g.fBig, pal::ICE, 250);
        std::string via = s.mode == VpnMode::Proxy ? "через VPN" : s.mode == VpnMode::Tun ? "через туннель" : "VPN не найден — реальный IP";
        text((s.exitg.country.empty() ? "" : s.exitg.country + " · ") + via, X(308), Y(ty + 54), g.fSmall, pal::STD, 250);
        if (s.mode == VpnMode::Proxy) {
            if (s.real.ip.empty())
                text("напрямую: не удалось узнать", X(308), Y(ty + 72), g.fSmall, pal::STD, 250);
            else if (s.real.ip == s.exitg.ip)
                text("напрямую тот же IP — прокси не меняет адрес!", X(308), Y(ty + 72), g.fSmall, pal::RED, 250);
            else
                text("напрямую: " + s.real.ip + (s.real.country.empty() ? "" : " · " + s.real.country),
                     X(308), Y(ty + 72), g.fSmall, pal::STD, 250);
        }
    }
    // --- плитка «VPN» ---
    D2D1_COLOR_F vcol = !s.have ? pal::STD : (s.mode == VpnMode::None ? pal::YEL : pal::GN);
    box(X(578), Y(ty), 268, th, s.have ? D2D1_COLOR_F{ vcol.r, vcol.g, vcol.b, 0.45f } : pal::BOXLN);
    textW(L"VPN", X(590), Y(ty + 10), g.fTiny, pal::STD);
    if (!s.have) textW(L"…", X(590), Y(ty + 28), g.fBig, pal::STD);
    else if (s.mode == VpnMode::Proxy) {
        textW(L"● ПРОКСИ", X(590), Y(ty + 27), g.fBig, pal::GN);
        std::string l1 = s.proxy + " (HTTP)";
        if (s.socksPort > 0) l1 += " · SOCKS5 :" + std::to_string(s.socksPort);
        text(l1, X(590), Y(ty + 54), g.fSmall, pal::STD, 250);
        text("маршрут по умолчанию — напрямую", X(590), Y(ty + 72), g.fSmall, pal::STD, 250);
    } else if (s.mode == VpnMode::Tun) {
        textW(L"● TUN", X(590), Y(ty + 27), g.fBig, pal::GN);
        text(s.tunName.empty() ? "туннельный адаптер" : "адаптер: " + s.tunName, X(590), Y(ty + 54), g.fSmall, pal::STD, 250);
        text("весь трафик идёт через туннель", X(590), Y(ty + 72), g.fSmall, pal::STD, 250);
    } else {
        textW(L"○ НЕ НАЙДЕН", X(590), Y(ty + 27), g.fBig, pal::YEL);
        text("нет ни системного прокси, ни TUN", X(590), Y(ty + 54), g.fSmall, pal::STD, 250);
        text("трафик идёт напрямую", X(590), Y(ty + 72), g.fSmall, pal::STD, 250);
    }

    // --- быстрый запуск ---
    textW(L"БЫСТРЫЙ ЗАПУСК", X(14), Y(142), g.fTiny, pal::AM);
    static const wchar_t* SUBT[SCR_COUNT] = { L"", L"напрямую / через VPN", L"HTTP + сравнение IP",
        L"TCP, nexttrace", L"баннеры, CVE", L"маршруты, утечки", L"", L"" };
    for (int i = 0; i < 5; i++) {
        int scr = SCR_SITES + i;
        float x = X(14 + 166.0f * i), y = Y(162), w = (i == 4) ? 168.0f : 158.0f, h = 84;
        bool busy = screenBusy(scr);
        box(x, y, w, h, busy ? pal::AM : pal::AMD, rgb(40, 30, 10, 0.55f));
        textW(std::to_wstring(i + 1) + L"  " + NAV[scr], x + 10, y + 9, g.fBold, pal::AM, w - 14);
        textW(SUBT[scr], x + 10, y + 31, g.fTiny, pal::STD, w - 14);
        if (busy) textW(L"● идёт… строк " + std::to_wstring(logCount(scr)), x + 10, y + 47, g.fTiny, pal::AM, w - 14);
        else      textW(g_lastSum[scr].text, x + 10, y + 47, g.fTiny, g_lastSum[scr].col, w - 14);
        std::wstring act = busy ? L"→ открыть" : L"▶ запуск";
        textW(act, x + w - 8 - textWidth(act, g.fTiny), y + h - 18, g.fTiny, pal::AM);
        addHit(x, y, x + w, y + h, [scr] { if (screenBusy(scr)) setScreen(scr); else startRun(scr); });
    }

    // --- последние отчёты ---
    textW(L"ПОСЛЕДНИЕ ОТЧЁТЫ", X(14), Y(266), g.fTiny, pal::AM);
    std::wstring all = L"все отчёты → раздел ОТЧЁТЫ";
    float aw = textWidth(all, g.fTiny);
    textW(all, X(846) - aw, Y(266), g.fTiny, pal::STD);
    addHit(X(846) - aw, Y(262), X(846), Y(280), [] { setScreen(SCR_REPORTS); });
    box(X(14), Y(286), 832, 196);
    float rx = X(26), ry = Y(294);
    textW(L"КОГДА", rx, ry, g.fTiny, pal::STD);
    textW(L"РАЗДЕЛ", rx + 150, ry, g.fTiny, pal::STD);
    textW(L"ПОДКЛЮЧЕНИЕ", rx + 270, ry, g.fTiny, pal::STD);
    textW(L"РАЗМЕР", rx + 630, ry, g.fTiny, pal::STD);
    if (g_reports.empty())
        textW(L"Отчётов пока нет — запусти любую проверку.", rx, ry + 30, g.fRegular, pal::STD);
    for (size_t i = 0; i < g_reports.size() && i < 6; i++) {
        const ReportFile& r = g_reports[i];
        float y = ry + 20 + i * 24.0f;
        textW(whenStr(r), rx, y, g.fRegular, pal::TX, 145, 22);
        textW(shortName(r.screen), rx + 150, y, g.fRegular, pal::AM, 115, 22);
        textW(W(r.conn), rx + 270, y, g.fRegular, pal::TX, 350, 22);
        textW(sizeStr(r.size), rx + 630, y, g.fRegular, pal::STD, 120, 22);
        std::wstring p = r.path;
        addHit(X(18), y - 3, X(842), y + 21, [p] { openReport(p); });
    }
}

// ===================== ОТЧЁТЫ =====================
static int g_repFilter = 0;             // 0 — все, 1..5 — САЙТЫ…СЕТЬ
static int g_repSel = 0;                // индекс в отфильтрованном списке
static int g_repTop = 0;                // первая видимая строка списка
static std::wstring g_repSelPath;       // выбранный файл (чтобы выбор не прыгал при пересканировании)
static std::wstring g_prevPath;         // какой файл сейчас в просмотре
static std::vector<LogLine> g_prevLines;
static int g_prevTop = 0;
static ULONGLONG g_delArm = 0;          // «точно удалить?» — когда нажали первый раз
static const int REP_ROWS = 14;         // строк списка на экране
static const float REP_ROWH = 27.0f;
static const int PREV_ROWS = 21;        // строк просмотра на экране
static const float PREV_ROWH = 16.0f;

static std::vector<int> repFiltered() {
    std::vector<int> v;
    for (int i = 0; i < (int)g_reports.size(); i++)
        if (g_repFilter == 0 || g_reports[i].screen == SCR_SITES + g_repFilter - 1) v.push_back(i);
    return v;
}
// раскраска строк отчёта в просмотре (в файле цветов нет — угадываем по содержимому)
static D2D1_COLOR_F previewColor(const std::string& l) {
    std::string t = trim(l);
    if (startsWith(t, "===") || startsWith(t, "---")) return pal::ICE;
    if (startsWith(t, "Дата и время") || startsWith(t, "IP проверяющего") || startsWith(t, "Лог-файл")) return pal::YEL;
    if (has(t, "[ПРОБЛЕМА]") || has(t, "УТЕЧКА")) return pal::RED;
    if (has(t, "CVE-")) return pal::YEL;
    if (has(t, "[OK]") || (has(t, "ОТКРЫТ") && !has(t, "ЗАКРЫТ"))) return pal::GN;
    if (has(t, "ЗАКРЫТ")) return pal::STD;
    return pal::TX;
}
static void loadPreview(const std::wstring& path) {
    if (path == g_prevPath) return;
    g_prevPath = path; g_prevLines.clear(); g_prevTop = 0;
    if (path.empty()) return;
    for (auto& l : readLines(path)) g_prevLines.push_back({ previewColor(l), toW(l) });
}
// держать выбранную строку в видимой части списка
static void repEnsureVisible() {
    if (g_repSel < g_repTop) g_repTop = g_repSel;
    if (g_repSel >= g_repTop + REP_ROWS) g_repTop = g_repSel - REP_ROWS + 1;
    if (g_repTop < 0) g_repTop = 0;
}
static void repSelect(int idx) {
    auto f = repFiltered();
    if (f.empty()) { g_repSel = 0; g_repSelPath.clear(); return; }
    g_repSel = std::max(0, std::min(idx, (int)f.size() - 1));
    g_repSelPath = g_reports[f[g_repSel]].path;
    g_delArm = 0;
    repEnsureVisible();
}
// после пересканирования найти тот же файл в списке
static void repResync() {
    auto f = repFiltered();
    for (int i = 0; i < (int)f.size(); i++)
        if (g_reports[f[i]].path == g_repSelPath) { g_repSel = i; repEnsureVisible(); return; }
    repSelect(std::min(g_repSel, (int)f.size() - 1));
}
static void openReport(const std::wstring& path) {   // клик по отчёту на главной
    g_repFilter = 0; g_repSelPath = path;
    repResync();
    setScreen(SCR_REPORTS);
}
static const ReportFile* repCurrent() {
    auto f = repFiltered();
    if (f.empty() || g_repSel < 0 || g_repSel >= (int)f.size()) return nullptr;
    return &g_reports[f[g_repSel]];
}
static void repOpenExternal() {
    if (auto r = repCurrent()) ShellExecuteW(g.hwnd, L"open", r->path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}
static void repOpenFolder() {
    if (auto r = repCurrent()) {
        std::wstring args = L"/select,\"" + r->path + L"\"";
        ShellExecuteW(g.hwnd, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    }
}
// удаление в два нажатия: первое «взводит», второе в течение 4 секунд — удаляет
static void repDelete() {
    const ReportFile* r = repCurrent();
    if (!r) return;
    ULONGLONG now = GetTickCount64();
    if (g_delArm == 0 || now - g_delArm > 4000) { g_delArm = now; return; }
    g_delArm = 0;
    std::wstring p = r->path;
    DeleteFileW(p.c_str());
    if (g_prevPath == p) { g_prevPath.clear(); g_prevLines.clear(); }
    int keep = g_repSel;
    scanReports();
    repSelect(keep);
}

static void drawReports() {
    auto f = repFiltered();
    std::wstring head = L"ОТЧЁТЫ  //  папка Logs · " + std::to_wstring(g_reports.size()) +
                        L" файлов · хранятся " + std::to_wstring(g_config.MaxLogAgeDays) + L" дней";
    textW(head, X(4), Y(2), g.fRegular, pal::AM);

    // вкладки-фильтры
    static const wchar_t* TABS[6] = { L"ВСЕ", L"САЙТЫ", L"DNS", L"ТРАССА", L"ПОРТЫ", L"СЕТЬ" };
    float tx = X(14);
    for (int i = 0; i < 6; i++) {
        float w = textWidth(TABS[i], g.fBold) + 26;
        bool on = (i == g_repFilter);
        rectFill(tx, Y(30), tx + w, Y(56), on ? pal::NAVON : rgb(0, 0, 0, 0));
        rectLine(tx, Y(30), tx + w, Y(56), on ? pal::AM : pal::BOXLN);
        textW(TABS[i], tx + 13, Y(34), on ? g.fBold : g.fRegular, on ? pal::AM : pal::NAVTX);
        addHit(tx, Y(30), tx + w, Y(56), [i] { g_repFilter = i; g_repTop = 0; repSelect(0); });
        tx += w + 6;
    }

    // список слева
    box(X(14), Y(66), 380, 418);
    float lx = X(22);
    textW(L"КОГДА", lx, Y(74), g.fTiny, pal::STD);
    textW(L"РАЗДЕЛ", lx + 100, Y(74), g.fTiny, pal::STD);
    textW(L"ПОДКЛЮЧЕНИЕ", lx + 172, Y(74), g.fTiny, pal::STD);
    textW(L"РАЗМ.", lx + 322, Y(74), g.fTiny, pal::STD);
    if (f.empty()) textW(L"Отчётов нет.", lx, Y(100), g.fRegular, pal::STD);
    for (int k = 0; k < REP_ROWS && g_repTop + k < (int)f.size(); k++) {
        int idx = g_repTop + k;
        const ReportFile& r = g_reports[f[idx]];
        float y = Y(92) + k * REP_ROWH;
        if (idx == g_repSel) {
            rectFill(X(18), y - 2, X(390), y + REP_ROWH - 4, pal::SEL);
            rectLine(X(18), y - 2, X(390), y + REP_ROWH - 4, pal::AMD);
        }
        textW(whenStr(r, false), lx, y + 3, g.fMid, pal::TX, 96, 20);
        textW(shortName(r.screen), lx + 100, y + 3, g.fMid, pal::AM, 70, 20);
        textW(W(r.conn), lx + 172, y + 3, g.fMid, pal::TX, 144, 20);
        textW(sizeStr(r.size), lx + 322, y + 3, g.fMid, pal::STD, 50, 20);
        addHit(X(18), y - 2, X(390), y + REP_ROWH - 4, [idx] { repSelect(idx); });
    }
    if ((int)f.size() > REP_ROWS) {   // полоса прокрутки списка
        float trackY = Y(92), trackH = REP_ROWS * REP_ROWH;
        float thumbH = trackH * REP_ROWS / f.size();
        float thumbY = trackY + trackH * g_repTop / f.size();
        rectFill(X(386), trackY, X(389), trackY + trackH, rgb(20, 40, 55));
        rectFill(X(386), thumbY, X(389), thumbY + thumbH, pal::AMD);
    }

    // просмотр справа
    const ReportFile* cur = repCurrent();
    loadPreview(cur ? cur->path : L"");
    box(X(406), Y(66), 440, 376);
    textW(L"ПРОСМОТР" + (cur ? L" · " + cur->name : std::wstring()), X(418), Y(74), g.fTiny, pal::STD, 420);
    if (cur) {
        int total = (int)g_prevLines.size();
        int maxTop = std::max(0, total - PREV_ROWS);
        g_prevTop = std::max(0, std::min(g_prevTop, maxTop));
        float py = Y(94);
        g.rt->PushAxisAlignedClip(D2D1::RectF(X(414), py, X(836), py + PREV_ROWS * PREV_ROWH), D2D1_ANTIALIAS_MODE_ALIASED);
        for (int k = 0; k < PREV_ROWS && g_prevTop + k < total; k++) {
            const LogLine& L = g_prevLines[g_prevTop + k];
            textW(L.text, X(418), py + k * PREV_ROWH, g.fMid, L.col, 418, PREV_ROWH);
        }
        g.rt->PopAxisAlignedClip();
        if (total > PREV_ROWS) {
            float trackH = PREV_ROWS * PREV_ROWH;
            float thumbH = trackH * PREV_ROWS / total;
            float thumbY = py + trackH * g_prevTop / total;
            rectFill(X(838), py, X(841), py + trackH, rgb(20, 40, 55));
            rectFill(X(838), thumbY, X(841), thumbY + thumbH, pal::AMD);
        }
    }

    // кнопки
    bool armed = g_delArm && GetTickCount64() - g_delArm <= 4000;
    int st = cur ? BTN_MAIN : BTN_OFF;
    button(X(406), Y(452), 150, 32, L"ОТКРЫТЬ", st, [] { repOpenExternal(); });
    button(X(566), Y(452), 130, 32, L"ПАПКА", cur ? BTN_SEC : BTN_OFF, [] { repOpenFolder(); });
    button(X(706), Y(452), 140, 32, armed ? L"ТОЧНО УДАЛИТЬ?" : L"УДАЛИТЬ", cur ? BTN_DANGER : BTN_OFF,
           [] { repDelete(); });
}

// ===================== НАСТРОЙКИ =====================
struct Param {
    const wchar_t* name; const wchar_t* note; const wchar_t* unit;
    int Config::* ptr;   // какое поле Config меняет эта строка
    int mn, mx, step;
};
static const Param PARAMS[5] = {
    { L"Таймаут подключения к порту", L"скан портов: сколько ждать ответа порта",      L"мс",   &Config::ConnectionTimeout, 50, 5000, 50 },
    { L"Ожидание баннера",            L"скан портов: сколько ждать приветствие сервиса", L"мс",   &Config::BannerTimeout,    200, 10000, 100 },
    { L"Таймаут HTTP",                L"проверка сайтов: дольше — считается timeout",   L"с",    &Config::HttpTimeout,        1, 30, 1 },
    { L"Максимум узлов трассы",       L"nexttrace --max-hops",                          L"",     &Config::MaxHops,            5, 64, 1 },
    { L"Хранить отчёты",              L"старые файлы в Logs удаляются при запуске",     L"дней", &Config::MaxLogAgeDays,      1, 365, 1 },
};
static const int SET_ROWS = 6;          // 5 ползунков + строка SOCKS
static Config g_edit;                   // редактируемая копия настроек (в файл — по «Сохранить»)
static int g_setSel = 0;                // выбранная строка
static int g_editField = -1;            // какое поле вводится с клавиатуры (0..4, 5 = SOCKS), -1 — никакое
static std::wstring g_editBuf;          // набираемое число
static int g_drag = -1;                 // какой ползунок тянут мышью
static ULONGLONG g_savedTick = 0;       // когда сохранили (для надписи «сохранено»)
enum { UPD_IDLE, UPD_CHECKING, UPD_LATEST, UPD_NEW, UPD_FAIL, UPD_UPDATING };
static std::atomic<int> g_upd{UPD_IDLE};
static std::string g_updRemote;         // версия на GitHub

static const float SL_X = 330, SL_W = 300;   // ползунок внутри строки
static float rowY(int i) { return 48.0f + 50.0f * i; }

static bool cfgEqual(const Config& a, const Config& b) {
    return a.ConnectionTimeout == b.ConnectionTimeout && a.BannerTimeout == b.BannerTimeout &&
           a.HttpTimeout == b.HttpTimeout && a.MaxLogAgeDays == b.MaxLogAgeDays &&
           a.MaxHops == b.MaxHops && a.SocksPort == b.SocksPort;
}
static bool setDirty() { return !cfgEqual(g_edit, g_config); }
static int clampParam(int i, int v) {
    const Param& p = PARAMS[i];
    return std::max(p.mn, std::min(p.mx, v));
}
static void setParam(int i, int v) { g_edit.*(PARAMS[i].ptr) = clampParam(i, v); }
// HTTP-порт текущего прокси (для «авто = HTTP − 1»), 0 — прокси нет
static int currentHttpPort() { std::lock_guard<std::mutex> lk(g_stMx); return g_st.httpPort; }

// ввод числа с клавиатуры: применить / отменить
static void commitEdit() {
    if (g_editField < 0) return;
    int v = 0;
    try { v = g_editBuf.empty() ? 0 : std::stoi(g_editBuf); } catch (...) { v = 0; }
    if (g_editField < 5) setParam(g_editField, v);
    else if (v >= 1 && v <= 65535) g_edit.SocksPort = v;
    g_editField = -1; g_editBuf.clear();
}
static void cancelEdit() { g_editField = -1; g_editBuf.clear(); }
static void beginEdit(int field) {
    commitEdit();
    g_editField = field;
    g_editBuf = std::to_wstring(field < 5 ? g_edit.*(PARAMS[field].ptr) : g_edit.SocksPort);
}
// ползунок по положению мыши
static void sliderFromMouse(int i) {
    const Param& p = PARAMS[i];
    float frac = (g.mouseX - X(14 + SL_X)) / SL_W;
    frac = std::max(0.0f, std::min(1.0f, frac));
    int v = p.mn + (int)((frac * (p.mx - p.mn)) / p.step + 0.5f) * p.step;
    setParam(i, v);
}
static void toggleSocksAuto() {
    commitEdit();
    if (g_edit.SocksPort > 0) g_edit.SocksPort = 0;
    else { int hp = currentHttpPort(); g_edit.SocksPort = hp > 1 ? hp - 1 : 10808; }
}
static void saveSettings() {
    commitEdit();
    g_config = g_edit;
    saveConfig();
    g_savedTick = GetTickCount64();
}
static void checkUpdates() {
    int st = g_upd.load();
    if (st == UPD_CHECKING || st == UPD_UPDATING) return;
    if (st == UPD_NEW) {                       // вторая стадия: скачать и поставить
        if (anyBusy()) return;                 // не обновляемся посреди проверки
        g_upd = UPD_UPDATING; g_bg++;
        std::thread([] {
            updateSelf();                      // при успехе сам закроет программу и перезапустит новую
            g_upd = UPD_FAIL; g_bg--; g_dirty = true;   // сюда попадём только при ошибке
        }).detach();
        return;
    }
    g_upd = UPD_CHECKING; g_bg++;
    std::thread([] {
        std::string rv = fetchRemoteVersion();
        g_updRemote = rv;
        g_upd = rv.empty() ? UPD_FAIL : (rv == SCRIPT_VERSION ? UPD_LATEST : UPD_NEW);
        g_bg--; g_dirty = true;
    }).detach();
}

static void drawSettings() {
    textW(L"НАСТРОЙКИ  //  Settings\\config.json", X(4), Y(2), g.fRegular, pal::AM);
    textW(L"ТАЙМАУТЫ И ЛИМИТЫ", X(14), Y(30), g.fTiny, pal::AM);

    for (int i = 0; i < 5; i++) {
        const Param& p = PARAMS[i];
        float y = Y(rowY(i));
        if (i == g_setSel) { rectFill(X(14), y, X(846), y + 46, rgb(240, 170, 60, 0.08f)); rectLine(X(14), y, X(846), y + 46, pal::AMD); }
        addHit(X(14), y, X(846), y + 46, [i] { commitEdit(); g_setSel = i; });   // клик по строке — выбрать
        textW(p.name, X(26), y + 6, g.fRegular, pal::TX, 300);
        textW(p.note, X(26), y + 25, g.fTiny, pal::STD, 300);
        // ползунок
        int v = g_edit.*(p.ptr);
        float frac = (float)(v - p.mn) / (p.mx - p.mn);
        frac = std::max(0.0f, std::min(1.0f, frac));
        float sx = X(14 + SL_X), sy = y + 21;
        rectFill(sx, sy, sx + SL_W, sy + 4, rgb(20, 40, 55));
        rectFill(sx, sy, sx + frac * SL_W, sy + 4, pal::AMD);
        rectFill(sx + frac * SL_W - 5, sy - 6, sx + frac * SL_W + 5, sy + 10, pal::AM);
        addHit(sx - 6, y + 6, sx + SL_W + 6, y + 40, [i] { commitEdit(); g_setSel = i; g_drag = i; sliderFromMouse(i); });
        // поле числа
        float fx = X(674), fy = y + 10;
        bool editing = (g_editField == i);
        rectFill(fx, fy, fx + 90, fy + 26, rgb(0, 0, 0, 0.35f));
        rectLine(fx, fy, fx + 90, fy + 26, editing ? pal::AM : rgb(70, 200, 200, 0.35f));
        textW(editing ? g_editBuf + L"_" : std::to_wstring(v), fx + 8, fy + 4, g.fRegular, pal::TX, 80);
        addHit(fx, fy, fx + 90, fy + 26, [i] { g_setSel = i; beginEdit(i); });
        textW(p.unit, fx + 100, fy + 5, g.fRegular, pal::STD);
    }

    // --- SOCKS ---
    textW(L"VPN-КЛИЕНТ", X(14), Y(308), g.fTiny, pal::AM);
    float sy = Y(322);
    if (g_setSel == 5) { rectFill(X(14), sy, X(846), sy + 46, rgb(240, 170, 60, 0.08f)); rectLine(X(14), sy, X(846), sy + 46, pal::AMD); }
    addHit(X(14), sy, X(846), sy + 46, [] { commitEdit(); g_setSel = 5; });
    textW(L"Порт SOCKS5 клиента", X(26), sy + 6, g.fRegular, pal::TX);
    textW(L"для v2rayN/Hiddify обычно на 1 меньше HTTP-порта", X(26), sy + 25, g.fTiny, pal::STD, 300);
    bool autoP = g_edit.SocksPort <= 0;
    int hp = currentHttpPort();
    std::wstring now = hp > 0 ? L"→ сейчас " + std::to_wstring(hp - 1) : L"→ прокси не задан";
    textW(autoP ? L"[■]" : L"[ ]", X(344), sy + 13, g.fRegular, pal::AM);
    textW(L"авто = HTTP − 1", X(380), sy + 13, g.fRegular, pal::TX);
    if (autoP) textW(now, X(520), sy + 13, g.fRegular, pal::STD);
    addHit(X(340), sy + 8, X(510), sy + 36, [] { g_setSel = 5; toggleSocksAuto(); });
    {
        float fx = X(674), fy = sy + 10;
        bool editing = (g_editField == 5);
        rectFill(fx, fy, fx + 90, fy + 26, rgb(0, 0, 0, autoP ? 0.15f : 0.35f));
        rectLine(fx, fy, fx + 90, fy + 26, editing ? pal::AM : rgb(70, 200, 200, autoP ? 0.15f : 0.35f));
        std::wstring val = editing ? g_editBuf + L"_" : (autoP ? (hp > 0 ? std::to_wstring(hp - 1) : L"авто") : std::to_wstring(g_edit.SocksPort));
        textW(val, fx + 8, fy + 4, g.fRegular, autoP ? pal::STD : pal::TX, 80);
        if (!autoP) addHit(fx, fy, fx + 90, fy + 26, [] { g_setSel = 5; beginEdit(5); });
    }

    // --- обновление ---
    textW(L"ОБНОВЛЕНИЕ", X(14), Y(386), g.fTiny, pal::AM);
    std::wstring ver = L"Версия " + toW(SCRIPT_VERSION) + L"  · GitHub Yozmor/lagg";
    textW(ver, X(26), Y(408), g.fRegular, pal::TX);
    float vx = X(26) + textWidth(ver, g.fRegular) + 14;
    int us = g_upd.load();
    if (us == UPD_LATEST)   textW(L"актуальная", vx, Y(408), g.fRegular, pal::GN);
    if (us == UPD_FAIL)     textW(L"GitHub недоступен", vx, Y(408), g.fRegular, pal::RED);
    if (us == UPD_NEW)      textW(anyBusy() ? L"есть v" + toW(g_updRemote) + L" · дождись конца проверок"
                                            : L"есть новая v" + toW(g_updRemote), vx, Y(408), g.fRegular, pal::YEL, 300);
    if (us == UPD_CHECKING) button(X(604), Y(400), 242, 32, L"ПРОВЕРЯЮ…", BTN_OFF);
    else if (us == UPD_UPDATING) button(X(604), Y(400), 242, 32, L"СКАЧИВАЮ…", BTN_OFF);
    else if (us == UPD_NEW) button(X(604), Y(400), 242, 32, L"ОБНОВИТЬ ДО v" + toW(g_updRemote),
                                   anyBusy() ? BTN_OFF : BTN_MAIN, [] { checkUpdates(); });
    else button(X(604), Y(400), 242, 32, L"ПРОВЕРИТЬ ОБНОВЛЕНИЯ", BTN_SEC, [] { checkUpdates(); });

    // --- сохранить / по умолчанию ---
    bool dirty = setDirty() || g_editField >= 0;
    button(X(14), Y(452), 200, 32, L"СОХРАНИТЬ  [Ctrl+S]", dirty ? BTN_MAIN : BTN_SEC, [] { saveSettings(); });
    button(X(224), Y(452), 180, 32, L"ПО УМОЛЧАНИЮ", BTN_SEC, [] { cancelEdit(); g_edit = Config{}; });
    if (dirty) textW(L"● есть несохранённые изменения", X(420), Y(460), g.fSmall, pal::AM);
    else if (g_savedTick && GetTickCount64() - g_savedTick < 3000)
        textW(L"✓ сохранено в config.json", X(420), Y(460), g.fSmall, pal::GN);
}

// ===================== СПИСКИ: РЕДАКТОРЫ ФАЙЛОВ ИЗ Settings =====================
// Вкладки: sites / dns / trace / scan — текстовые списки «значение;комментарий»,
// ports — плитки портов и диапазонов. Правки живут в памяти, в файл — по «Сохранить».
enum { LT_SITES, LT_DNS, LT_TRACE, LT_SCAN, LT_PORTS, LT_COUNT };
static const wchar_t* LT_TAB[LT_COUNT]  = { L"sites", L"dns", L"trace", L"scan", L"ports" };
static const wchar_t* LT_FILE[LT_COUNT] = { L"sites.txt", L"dns_targets.txt", L"trace_targets.txt",
                                            L"scan_targets.txt", L"ports.txt" };
static const wchar_t* LT_COL[LT_COUNT]  = { L"ДОМЕН", L"DNS-СЕРВЕР", L"IP / ДОМЕН", L"IP / ДОМЕН", L"" };

// строка текстового списка
enum { ROW_ITEM, ROW_GROUP, ROW_NOTE, ROW_BLANK };   // значение / «# --- группа ---» / «# заметка» / пустая
struct EdRow {
    int kind = ROW_ITEM;
    std::string value, comment;   // для ROW_ITEM
    std::string text;             // для группы и заметки — текст после «#»
    bool isNew = false;
};
struct TextList {
    bool loaded = false;
    std::vector<EdRow> rows;      // все строки файла по порядку (пустые тоже — чтобы сохранить как было)
    int sel = 0;                  // выбранная строка (индекс среди видимых)
    int top = 0;                  // первая видимая строка
    int changes = 0;              // счётчик правок с последней загрузки/сохранения
};
static TextList g_tl[4];
static int g_ltab = LT_SITES;     // активная вкладка

// правка строки «на месте»
static bool g_rowEditing = false;
static int  g_rowEditField = 0;   // 0 — значение (или текст группы), 1 — комментарий
static std::wstring g_rowVal, g_rowCom;
static bool g_rowEditIsNew = false;   // строку только что добавили — Esc её удалит

// плитки портов
struct PortTile { int from = 0, to = 0; std::string comment; };
static struct {
    bool loaded = false;
    std::vector<PortTile> tiles;
    int sel = 0;
    int topRow = 0;               // прокрутка сетки (в рядах)
    int changes = 0;
    std::vector<std::string> head;   // строки-заметки «#» из файла — сохраняем сверху как были
} g_pl;
static bool g_portFocus = false;  // курсор в поле «Добавить»
static std::wstring g_portBuf;
static std::string  g_portMsg;    // подсказка под полем
static bool g_pcFocus = false;    // курсор в поле «Комментарий» выбранной плитки
static std::wstring g_pcBuf;
static bool g_portMsgOk = false;

static const int TL_ROWS = 14;            // строк таблицы на экране
static const float TL_ROWH = 27.0f;
static const int PT_COLS = 8, PT_ROWS = 5;   // сетка плиток
static const float PT_W = 96, PT_H = 46, PT_GAP = 8;

// ---------- проверка значений ----------
static bool isIPv4(const std::string& s) {
    int parts = 0; size_t i = 0;
    while (i <= s.size()) {
        size_t j = s.find('.', i); if (j == std::string::npos) j = s.size();
        std::string p = s.substr(i, j - i);
        if (p.empty() || p.size() > 3) return false;
        for (char c : p) if (c < '0' || c > '9') return false;
        if (std::stoi(p) > 255) return false;
        parts++; i = j + 1;
        if (j == s.size()) break;
    }
    return parts == 4;
}
static bool looksIPv6(const std::string& s) {
    if (s.find(':') == std::string::npos) return false;
    for (char c : s) if (!(isxdigit((unsigned char)c) || c == ':' || c == '.')) return false;
    return true;
}
// домен: метки из букв/цифр/дефиса через точку; русские буквы тоже можно (сайт.рф)
static std::string domainError(const std::string& s) {
    if (s.find(' ') != std::string::npos || s.find('\t') != std::string::npos) return "пробел в домене";
    if (s.find("://") != std::string::npos) return "без http:// — только домен";
    if (s.find('/') != std::string::npos) return "без пути «/…» — только домен";
    if (s.find(';') != std::string::npos) return "«;» отделяет комментарий";
    if (s.find('.') == std::string::npos) return "нет точки — это не домен";
    if (s.front() == '.' || s.back() == '.' || s.find("..") != std::string::npos) return "пустая часть между точками";
    for (unsigned char c : s) {
        if (c >= 0x80) continue;   // байты UTF-8 (кириллица)
        if (!(isalnum(c) || c == '-' || c == '.')) return std::string("недопустимый символ «") + (char)c + "»";
    }
    return "";
}
// ошибка значения для вкладки ("" — всё верно)
static std::string valueError(int tab, const std::string& v) {
    if (v.empty()) return "пустое значение";
    if (tab == LT_SITES) return domainError(v);
    if (tab == LT_DNS) return isIPv4(v) ? "" : "не IPv4 (нужно вида 8.8.8.8)";
    // trace / scan: IP или домен
    if (isIPv4(v) || looksIPv6(v)) return "";
    bool digitsDots = true; for (char c : v) if (!(isdigit((unsigned char)c) || c == '.')) digitsDots = false;
    if (digitsDots) return "неверный IPv4";
    return domainError(v);
}

// ---------- загрузка и сохранение текстовых списков ----------
static std::wstring settingsPath(int tab) { return g_settingsDir + L"\\" + LT_FILE[tab]; }
static bool isGroupText(const std::string& t) {   // «# --- Название ---» — заголовок группы
    std::string x = trim(t);
    return startsWith(x, "---") || startsWith(x, "===");
}
static void loadTextList(int tab) {
    TextList& L = g_tl[tab];
    L = TextList{};
    L.loaded = true;
    std::ifstream f(settingsPath(tab), std::ios::binary);
    if (!f) {   // файла нет — начнём с подсказки
        EdRow r; r.kind = ROW_NOTE; r.text = " Формат: значение;комментарий";
        L.rows.push_back(r);
        return;
    }
    std::string line; bool first = true;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first && line.size() >= 3 && (unsigned char)line[0] == 0xEF) line = line.substr(3);   // BOM
        first = false;
        EdRow r;
        std::string t = trim(line);
        if (t.empty()) r.kind = ROW_BLANK;
        else if (t[0] == '#') { r.text = t.substr(1); r.kind = isGroupText(r.text) ? ROW_GROUP : ROW_NOTE; }
        else {
            size_t p = t.find(';');
            r.value   = trim(p == std::string::npos ? t : t.substr(0, p));
            r.comment = p == std::string::npos ? "" : trim(t.substr(p + 1));
        }
        L.rows.push_back(r);
    }
    while (!L.rows.empty() && L.rows.back().kind == ROW_BLANK) L.rows.pop_back();   // хвост пустых строк
}
// индексы видимых строк (пустые не показываем, но храним)
static std::vector<int> tlVisible(const TextList& L) {
    std::vector<int> v;
    for (int i = 0; i < (int)L.rows.size(); i++) if (L.rows[i].kind != ROW_BLANK) v.push_back(i);
    return v;
}
static int tlItemCount(const TextList& L) {
    int n = 0; for (auto& r : L.rows) if (r.kind == ROW_ITEM) n++; return n;
}
static int tlErrorCount(int tab) {
    int n = 0; for (auto& r : g_tl[tab].rows) if (r.kind == ROW_ITEM && !valueError(tab, r.value).empty()) n++;
    return n;
}
static bool saveTextList(int tab) {
    TextList& L = g_tl[tab];
    std::ofstream o(settingsPath(tab), std::ios::binary);
    if (!o) return false;
    for (auto& r : L.rows) {
        if (r.kind == ROW_BLANK) o << "\r\n";
        else if (r.kind == ROW_ITEM) o << r.value << (r.comment.empty() ? "" : ";" + r.comment) << "\r\n";
        else o << "#" << r.text << "\r\n";
    }
    for (auto& r : L.rows) r.isNew = false;
    L.changes = 0;
    return true;
}

// ---------- загрузка и сохранение портов ----------
static void portSort();   // ниже
static void loadPortList() {
    g_pl.tiles.clear(); g_pl.head.clear();
    g_pl.loaded = true; g_pl.sel = 0; g_pl.topRow = 0; g_pl.changes = 0;
    std::wstring path = settingsPath(LT_PORTS);
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) writeDefaultPorts(path);
    std::ifstream f(path, std::ios::binary);
    std::string line; bool first = true;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first && line.size() >= 3 && (unsigned char)line[0] == 0xEF) line = line.substr(3);
        first = false;
        std::string t = trim(line);
        if (t.empty()) continue;
        if (t[0] == '#') { g_pl.head.push_back(t); continue; }
        size_t sc = t.find(';');
        PortTile pt;
        if (!parsePortSpec(sc == std::string::npos ? t : t.substr(0, sc), pt.from, pt.to).empty()) continue;
        pt.comment = sc == std::string::npos ? "" : trim(t.substr(sc + 1));
        g_pl.tiles.push_back(pt);
    }
    g_pl.sel = 0; portSort(); g_pl.sel = 0;
}
static bool savePortList() {
    std::ofstream o(settingsPath(LT_PORTS), std::ios::binary);
    if (!o) return false;
    if (g_pl.head.empty()) o << "# Порты для сканирования\r\n# Формат: порт или диапазон от-до;комментарий\r\n";
    for (auto& h : g_pl.head) o << h << "\r\n";
    for (auto& t : g_pl.tiles) {
        if (t.from == t.to) o << t.from; else o << t.from << "-" << t.to;
        std::string c = t.comment.empty() && t.from == t.to ? portName(t.from) : t.comment;
        if (!c.empty()) o << ";" << c;
        o << "\r\n";
    }
    g_pl.changes = 0;
    return true;
}
static int portTotal() {   // сколько уникальных портов уйдёт в скан
    std::vector<bool> seen(65536, false); int n = 0;
    for (auto& t : g_pl.tiles) for (int p = t.from; p <= t.to; p++) if (!seen[p]) { seen[p] = true; n++; }
    return n;
}
static bool portCovered(int a, int b) {   // весь диапазон a..b уже есть в плитках
    for (int p = a; p <= b; p++) {
        bool in = false;
        for (auto& t : g_pl.tiles) if (p >= t.from && p <= t.to) { in = true; break; }
        if (!in) return false;
    }
    return true;
}
// проверка того, что набрано в поле «Добавить» (обновляет подсказку)
static bool portCheckInput(int& a, int& b) {
    std::string in = toU8(g_portBuf);
    if (trim(in).empty()) { g_portMsg.clear(); return false; }
    std::string err = parsePortSpec(in, a, b);
    if (!err.empty()) { g_portMsg = err; g_portMsgOk = false; return false; }
    if (portCovered(a, b)) { g_portMsg = a == b ? "этот порт уже есть" : "все эти порты уже есть"; g_portMsgOk = false; return false; }
    g_portMsg = a == b ? "порт " + std::to_string(a) + (portName(a).empty() ? "" : " · " + portName(a))
                       : "диапазон, " + std::to_string(b - a + 1) + " портов";
    g_portMsgOk = true;
    return true;
}
// плитки по возрастанию номера; выбор остаётся на той же плитке
static void portSort() {
    if (g_pl.tiles.empty()) return;
    PortTile cur = g_pl.tiles[std::min(g_pl.sel, (int)g_pl.tiles.size() - 1)];
    std::stable_sort(g_pl.tiles.begin(), g_pl.tiles.end(),
        [](const PortTile& a, const PortTile& b) { return a.from != b.from ? a.from < b.from : a.to < b.to; });
    for (int i = 0; i < (int)g_pl.tiles.size(); i++)
        if (g_pl.tiles[i].from == cur.from && g_pl.tiles[i].to == cur.to) { g_pl.sel = i; break; }
}
static void portAdd() {
    int a, b;
    if (!portCheckInput(a, b)) return;
    PortTile t; t.from = a; t.to = b;
    g_pl.tiles.push_back(t);
    g_pl.sel = (int)g_pl.tiles.size() - 1;
    portSort();
    g_pl.changes++;
    g_portBuf.clear(); g_portMsg = "добавлено"; g_portMsgOk = true;
}
// комментарий выбранной плитки: начать правку / применить / отменить
static void pcBegin() {
    if (g_pl.tiles.empty()) return;
    g_portFocus = false; g_pcFocus = true;
    const PortTile& t = g_pl.tiles[g_pl.sel];
    g_pcBuf = toW(!t.comment.empty() ? t.comment : (t.from == t.to ? portName(t.from) : ""));
}
static void pcCommit() {
    if (!g_pcFocus) return;
    g_pcFocus = false;
    if (g_pl.tiles.empty()) return;
    PortTile& t = g_pl.tiles[g_pl.sel];
    std::string c = trim(toU8(g_pcBuf));
    if (c != t.comment) { t.comment = c; g_pl.changes++; }
}
static void portRemove() {
    if (g_pl.tiles.empty()) return;
    g_pl.tiles.erase(g_pl.tiles.begin() + g_pl.sel);
    if (g_pl.sel >= (int)g_pl.tiles.size()) g_pl.sel = std::max(0, (int)g_pl.tiles.size() - 1);
    g_pl.changes++;
}
static void portDefaults() {
    g_pl.tiles.clear();
    for (int p : DEFAULT_PORTS) { PortTile t; t.from = t.to = p; t.comment = portName(p); g_pl.tiles.push_back(t); }
    g_pl.sel = 0; g_pl.topRow = 0; g_pl.changes++;
}

// ---------- действия со строками текстового списка ----------
static TextList& curTL() { return g_tl[std::min(g_ltab, 3)]; }   // только текстовые вкладки
static int tlRowIndex() {   // индекс выбранной строки в rows (или -1)
    TextList& L = curTL(); auto v = tlVisible(L);
    if (v.empty()) return -1;
    L.sel = std::max(0, std::min(L.sel, (int)v.size() - 1));
    return v[L.sel];
}
static void tlEnsureVisible() {
    TextList& L = curTL();
    if (L.sel < L.top) L.top = L.sel;
    if (L.sel >= L.top + TL_ROWS) L.top = L.sel - TL_ROWS + 1;
    if (L.top < 0) L.top = 0;
}
static void tlSelect(int i) {
    TextList& L = curTL(); int n = (int)tlVisible(L).size();
    L.sel = n ? std::max(0, std::min(i, n - 1)) : 0;
    tlEnsureVisible();
}
static void rowBeginEdit(bool isNew = false) {
    int ri = tlRowIndex(); if (ri < 0) return;
    EdRow& r = curTL().rows[ri];
    g_rowEditing = true; g_rowEditField = 0; g_rowEditIsNew = isNew;
    if (r.kind == ROW_ITEM) { g_rowVal = toW(r.value); g_rowCom = toW(r.comment); }
    else { g_rowVal = toW(trim(r.text)); g_rowCom.clear(); }
}
static void rowCommitEdit() {
    if (!g_rowEditing) return;
    g_rowEditing = false;
    int ri = tlRowIndex(); if (ri < 0) return;
    EdRow& r = curTL().rows[ri];
    std::string v = trim(toU8(g_rowVal));
    if (r.kind == ROW_ITEM) {
        std::string c = trim(toU8(g_rowCom));
        if (v.empty() && g_rowEditIsNew) {   // ничего не ввели в новую строку — убрать её
            curTL().rows.erase(curTL().rows.begin() + ri); curTL().changes--; tlSelect(curTL().sel);
            g_rowEditIsNew = false; return;
        }
        if (v != r.value || c != r.comment) { r.value = v; r.comment = c; curTL().changes++; }
    } else {
        std::string t = " " + v;
        if (r.kind == ROW_GROUP && !isGroupText(v)) t = " --- " + v + " ---";   // оформить как группу
        if (t != r.text) { r.text = t; curTL().changes++; }
    }
    g_rowEditIsNew = false;
}
static void rowCancelEdit() {
    if (!g_rowEditing) return;
    g_rowEditing = false;
    if (g_rowEditIsNew) {   // отменили только что добавленную строку — убрать её
        int ri = tlRowIndex();
        if (ri >= 0) {
            auto& rows = curTL().rows;
            bool grp = rows[ri].kind == ROW_GROUP;
            rows.erase(rows.begin() + ri);
            if (grp && ri > 0 && rows[ri - 1].kind == ROW_BLANK) rows.erase(rows.begin() + ri - 1);   // и пустую строку перед ней
            curTL().changes--; tlSelect(curTL().sel);
        }
    }
    g_rowEditIsNew = false;
}
// вставить строку после выбранной и сразу начать правку
static void rowInsert(int kind) {
    rowCommitEdit();
    TextList& L = curTL();
    int ri = tlRowIndex();
    int at = ri < 0 ? (int)L.rows.size() : ri + 1;
    EdRow r; r.kind = kind; r.isNew = true;
    if (kind == ROW_GROUP) {
        r.text = " --- Новая группа ---";
        EdRow blank; blank.kind = ROW_BLANK;            // пустая строка перед группой — как в файле
        L.rows.insert(L.rows.begin() + at, blank); at++;
    }
    L.rows.insert(L.rows.begin() + at, r);
    L.changes++;
    auto v = tlVisible(L);
    for (int i = 0; i < (int)v.size(); i++) if (v[i] == at) { L.sel = i; break; }
    tlEnsureVisible();
    rowBeginEdit(true);
}
static void rowDelete() {
    rowCommitEdit();
    TextList& L = curTL(); int ri = tlRowIndex(); if (ri < 0) return;
    L.rows.erase(L.rows.begin() + ri);
    L.changes++;
    tlSelect(L.sel);
}
// переместить выбранную строку на одну видимую позицию вверх/вниз
static void rowMove(int dir) {
    rowCommitEdit();
    TextList& L = curTL(); auto v = tlVisible(L);
    int j = L.sel + dir;
    if (L.sel < 0 || L.sel >= (int)v.size() || j < 0 || j >= (int)v.size()) return;
    std::swap(L.rows[v[L.sel]], L.rows[v[j]]);
    L.sel = j; L.changes++;
    tlEnsureVisible();
}
static void listsReload(int tab) {
    if (tab == LT_PORTS) { loadPortList(); g_portBuf.clear(); g_portMsg.clear(); }
    else loadTextList(tab);
    g_rowEditing = false;
}
static int listChanges(int tab) { return tab == LT_PORTS ? g_pl.changes : g_tl[tab].changes; }
static bool listCanSave(int tab) { return tab == LT_PORTS || tlErrorCount(tab) == 0; }
static void listsSave() {
    rowCommitEdit();
    if (!listCanSave(g_ltab)) return;
    if (g_ltab == LT_PORTS) savePortList(); else saveTextList(g_ltab);
}
static void listsSetTab(int t) {
    rowCommitEdit(); pcCommit();
    g_portFocus = false;
    g_ltab = (t + LT_COUNT) % LT_COUNT;
    if (g_ltab == LT_PORTS ? !g_pl.loaded : !g_tl[g_ltab].loaded) listsReload(g_ltab);
}
static void listsEnsureLoaded() {
    for (int t = 0; t < 4; t++) if (!g_tl[t].loaded) loadTextList(t);
    if (!g_pl.loaded) loadPortList();
}
// переход между полями правки (Tab) и вставка из буфера обмена (Ctrl+V)
static std::wstring* activeTextField() {
    if (g_rowEditing) return g_rowEditField == 0 ? &g_rowVal : &g_rowCom;
    if (g_portFocus) return &g_portBuf;
    if (g_pcFocus) return &g_pcBuf;
    return nullptr;
}
static void pasteClipboard() {
    std::wstring* f = activeTextField(); if (!f) return;
    if (!OpenClipboard(g.hwnd)) return;
    if (HANDLE h = GetClipboardData(CF_UNICODETEXT)) {
        if (auto p = (const wchar_t*)GlobalLock(h)) {
            for (const wchar_t* c = p; *c && f->size() < 200; c++)
                if (*c != L'\r' && *c != L'\n' && *c != L'\t') f->push_back(*c);
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
}

// ---------- рисование ----------
static void drawFieldBox(float x, float y, float w, float h, const std::wstring& val, bool focus, IDWriteTextFormat* f) {
    rectFill(x, y, x + w, y + h, rgb(0, 0, 0, 0.35f));
    rectLine(x, y, x + w, y + h, focus ? pal::AM : rgb(70, 200, 200, 0.35f));
    std::wstring shown = val + (focus ? L"_" : L"");
    float tw = textWidth(shown, f);
    float off = tw > w - 12 ? (w - 12) - tw : 0;   // длинный текст — видим его конец
    g.rt->PushAxisAlignedClip(D2D1::RectF(x + 2, y, x + w - 2, y + h), D2D1_ANTIALIAS_MODE_ALIASED);
    textW(shown, x + 6 + off, y + (h - 15) / 2, f, pal::TX, std::max(w, tw + 20), h);
    g.rt->PopAxisAlignedClip();
}

static void drawTextListTab() {
    TextList& L = curTL();
    auto vis = tlVisible(L);
    int errs = tlErrorCount(g_ltab);

    // таблица
    box(X(14), Y(66), 580, 418);
    float lx = X(22);
    textW(L"№", lx, Y(74), g.fTiny, pal::STD);
    textW(LT_COL[g_ltab], lx + 34, Y(74), g.fTiny, pal::STD);
    textW(L"КОММЕНТАРИЙ", lx + 264, Y(74), g.fTiny, pal::STD);
    line(X(20), Y(90), X(588), Y(90), pal::BOXLN);
    if (vis.empty()) textW(L"Список пуст — нажми «+ Добавить».", lx, Y(100), g.fRegular, pal::STD);

    // номера считаем только по значениям (группы и заметки без номера)
    std::vector<int> num(L.rows.size(), 0);
    { int k = 0; for (size_t i = 0; i < L.rows.size(); i++) if (L.rows[i].kind == ROW_ITEM) num[i] = ++k; }
    // повторы значений — подсветим жёлтым (не мешают сохранению)
    std::map<std::string, int> cnt;
    for (auto& r : L.rows) if (r.kind == ROW_ITEM) cnt[r.value]++;

    for (int k = 0; k < TL_ROWS && L.top + k < (int)vis.size(); k++) {
        int vi = L.top + k;
        const EdRow& r = L.rows[vis[vi]];
        float y = Y(94) + k * TL_ROWH;
        bool sel = (vi == L.sel);
        bool editing = sel && g_rowEditing;
        if (sel) { rectFill(X(18), y, X(590), y + TL_ROWH - 2, pal::SEL); rectLine(X(18), y, X(590), y + TL_ROWH - 2, pal::AMD); }
        addHit(X(18), y, X(590), y + TL_ROWH - 2, [vi] {
            if (g_rowEditing && curTL().sel == vi) return;   // клик по своей же строке при правке — ничего
            rowCommitEdit(); tlSelect(vi);
        });
        float ty = y + 5;
        if (r.kind == ROW_GROUP || r.kind == ROW_NOTE) {
            if (r.kind == ROW_GROUP && !sel) line(X(20), y, X(588), y, rgb(240, 170, 60, 0.25f));
            if (editing) {
                drawFieldBox(lx + 34, y + 2, 500, TL_ROWH - 6, g_rowVal, true, g.fMid);
            } else if (r.kind == ROW_GROUP) {
                textW(L"▾ " + toW(trim(r.text)), lx, ty, g.fBold, pal::AM, 560, 20);
            } else {
                textW(L"# " + toW(trim(r.text)), lx, ty, g.fMid, pal::STD, 560, 20);
            }
            continue;
        }
        textW(std::to_wstring(num[vis[vi]]), lx, ty, g.fMid, pal::STD, 30, 20);
        if (editing) {
            drawFieldBox(lx + 34, y + 2, 222, TL_ROWH - 6, g_rowVal, g_rowEditField == 0, g.fMid);
            drawFieldBox(lx + 264, y + 2, 296, TL_ROWH - 6, g_rowCom, g_rowEditField == 1, g.fMid);
            addHit(lx + 34, y + 2, lx + 256, y + TL_ROWH - 4, [] { g_rowEditField = 0; });
            addHit(lx + 264, y + 2, lx + 560, y + TL_ROWH - 4, [] { g_rowEditField = 1; });
            // подсказка об ошибке прямо под строкой правки — в футер панели справа
            continue;
        }
        std::string err = valueError(g_ltab, r.value);
        if (!err.empty()) {
            textW(toW(r.value) + L"  ✕", lx + 34, ty, g.fMid, pal::RED, 226, 20);
            textW(toW(err), lx + 264, ty + 1, g.fSmall, pal::RED, 296, 20);
        } else {
            std::wstring v = toW(r.value);
            textW(v, lx + 34, ty, g.fMid, pal::TX, 226, 20);
            float vx = lx + 34 + std::min(textWidth(v, g.fMid), 200.0f) + 8;
            if (r.isNew) textW(L"новый", vx, ty + 2, g.fTiny, pal::GN);
            else if (cnt[r.value] > 1) textW(L"повтор", vx, ty + 2, g.fTiny, pal::YEL);
            textW(toW(r.comment), lx + 264, ty, g.fMid, pal::STD, 296, 20);
        }
    }
    if ((int)vis.size() > TL_ROWS) {   // полоса прокрутки
        float trackY = Y(94), trackH = TL_ROWS * TL_ROWH;
        float thumbH = trackH * TL_ROWS / vis.size();
        float thumbY = trackY + trackH * L.top / vis.size();
        rectFill(X(590), trackY, X(593), trackY + trackH, rgb(20, 40, 55));
        rectFill(X(590), thumbY, X(593), thumbY + thumbH, pal::AMD);
    }

    // справка о формате
    box(X(606), Y(66), 240, 150);
    float fx = X(618), fy = Y(76);
    textW(L"ФОРМАТ", fx, fy, g.fTiny, pal::STD);
    static const wchar_t* F1[4] = { L"домен без http:// и пути", L"IPv4-адрес DNS-сервера",
                                    L"IP или домен VPN-сервера", L"IP или домен сервера" };
    static const wchar_t* F2[4] = { L"t.me · www.youtube.com", L"8.8.8.8 · 1.1.1.1 · 77.88.8.8",
                                    L"203.0.113.10 · vpn.site.ru", L"сканируй только свои!" };
    textW(F1[g_ltab], fx, fy + 20, g.fMid, pal::TX, 220);
    textW(F2[g_ltab], fx, fy + 38, g.fSmall, g_ltab == LT_SCAN ? pal::YEL : pal::STD, 220);
    textW(L"комментарий — что угодно", fx, fy + 62, g.fMid, pal::TX, 220);
    textW(L"▾ группа = «# --- … ---»", fx, fy + 86, g.fMid, pal::AM, 220);
    textW(L"Tab — поле, Ctrl+V — вставить", fx, fy + 106, g.fSmall, pal::STD, 220);

    // кнопки
    button(X(606), Y(228), 240, 32, L"+ ДОБАВИТЬ  [Ins]", BTN_SEC, [] { rowInsert(ROW_ITEM); });
    button(X(606), Y(268), 240, 32, L"+ ГРУППА", BTN_SEC, [] { rowInsert(ROW_GROUP); });
    bool anyRows = !vis.empty();
    button(X(606), Y(308), 116, 32, L"↑ ВЫШЕ", anyRows ? BTN_SEC : BTN_OFF, [] { rowMove(-1); });
    button(X(730), Y(308), 116, 32, L"↓ НИЖЕ", anyRows ? BTN_SEC : BTN_OFF, [] { rowMove(+1); });
    button(X(606), Y(348), 240, 32, L"УДАЛИТЬ  [Del]", anyRows ? BTN_DANGER : BTN_OFF, [] { rowDelete(); });

    // состояние
    float sy = Y(396);
    if (g_rowEditing) {
        int ri = tlRowIndex();
        bool item = ri >= 0 && L.rows[ri].kind == ROW_ITEM;
        std::string err = item ? valueError(g_ltab, trim(toU8(g_rowVal))) : "";
        if (!err.empty()) textW(L"✕ " + toW(err), X(606), sy, g.fSmall, pal::RED, 240);
        else textW(L"Enter — готово, Esc — отмена", X(606), sy, g.fSmall, pal::STD, 240);
        sy += 18;
    }
    if (L.changes > 0) { textW(L"● изменений: " + std::to_wstring(L.changes), X(606), sy, g.fSmall, pal::AM, 240); sy += 18; }
    if (errs > 0) textW(L"✕ ошибок: " + std::to_wstring(errs) + L" — сохранить нельзя", X(606), sy, g.fSmall, pal::RED, 240);
    bool canSave = (L.changes > 0 || g_rowEditing) && errs == 0;
    button(X(606), Y(452), 116, 32, L"СОХРАНИТЬ", canSave ? BTN_MAIN : BTN_OFF, [] { listsSave(); });
    button(X(730), Y(452), 116, 32, L"ОТМЕНИТЬ", (L.changes > 0 || g_rowEditing) ? BTN_SEC : BTN_OFF,
           [] { listsReload(g_ltab); });
}

// раскладка плиток: где стоит каждая (диапазон занимает 2 клетки)
struct TilePos { int row, col, span; };
static std::vector<TilePos> portLayout() {
    std::vector<TilePos> pos; int row = 0, col = 0;
    for (auto& t : g_pl.tiles) {
        int span = t.from == t.to ? 1 : 2;
        if (col + span > PT_COLS) { row++; col = 0; }
        pos.push_back({ row, col, span });
        col += span;
        if (col >= PT_COLS) { row++; col = 0; }
    }
    return pos;
}
static void portEnsureVisible() {
    auto pos = portLayout();
    if (pos.empty()) return;
    int r = pos[std::max(0, std::min(g_pl.sel, (int)pos.size() - 1))].row;
    if (r < g_pl.topRow) g_pl.topRow = r;
    if (r >= g_pl.topRow + PT_ROWS) g_pl.topRow = r - PT_ROWS + 1;
}
// стрелки вверх/вниз по сетке: ближайшая плитка в соседнем ряду
static void portMoveVert(int dir) {
    auto pos = portLayout();
    if (pos.empty()) return;
    const TilePos& c = pos[g_pl.sel];
    int best = -1, bestD = 1000;
    for (int i = 0; i < (int)pos.size(); i++)
        if (pos[i].row == c.row + dir) { int d = abs(pos[i].col - c.col); if (d < bestD) { bestD = d; best = i; } }
    if (best >= 0) g_pl.sel = best;
}

static void drawPortsTab() {
    textW(L"ПОРТЫ ДЛЯ СКАНИРОВАНИЯ · плиток " + std::to_wstring(g_pl.tiles.size()) +
          L" · всего портов " + std::to_wstring(portTotal()), X(14), Y(70), g.fTiny, pal::AM);
    auto pos = portLayout();
    int rowsTotal = pos.empty() ? 0 : pos.back().row + 1;
    g_pl.topRow = std::max(0, std::min(g_pl.topRow, std::max(0, rowsTotal - PT_ROWS)));
    if (g_pl.tiles.empty()) textW(L"Портов нет — добавь ниже или нажми «По умолчанию».", X(14), Y(100), g.fRegular, pal::STD);
    for (int i = 0; i < (int)g_pl.tiles.size(); i++) {
        const TilePos& p = pos[i];
        if (p.row < g_pl.topRow || p.row >= g_pl.topRow + PT_ROWS) continue;
        const PortTile& t = g_pl.tiles[i];
        float x = X(14 + p.col * (PT_W + PT_GAP)), y = Y(90 + (p.row - g_pl.topRow) * (PT_H + PT_GAP));
        float w = p.span * PT_W + (p.span - 1) * PT_GAP;
        bool sel = (i == g_pl.sel) && !g_portFocus;
        bool range = t.from != t.to;
        D2D1_COLOR_F bord = range ? (sel ? pal::ICE : rgb(70, 200, 200, 0.6f)) : (sel ? pal::AM : pal::AMD);
        D2D1_COLOR_F fill = range ? rgb(70, 200, 200, sel ? 0.14f : 0.06f) : (sel ? rgb(240, 170, 60, 0.15f) : rgb(40, 30, 10, 0.55f));
        box(x, y, w, PT_H, bord, fill);
        std::wstring num = range ? std::to_wstring(t.from) + L"-" + std::to_wstring(t.to) : std::to_wstring(t.from);
        textW(num, x + 8, y + 5, g.fBold, range ? pal::ICE : pal::AM, w - 20);
        std::string sub = range ? "диапазон · " + std::to_string(t.to - t.from + 1) + " портов"
                                : (!t.comment.empty() ? t.comment : (portName(t.from).empty() ? "—" : portName(t.from)));
        text(sub, x + 8, y + 26, g.fTiny, pal::STD, w - 12);
        addHit(x, y, x + w, y + PT_H, [i] { pcCommit(); g_portFocus = false; g_pl.sel = i; });
        if (i == g_pl.sel && g_pcFocus) rectLine(x, y, x + w, y + PT_H, pal::AM, 2.0f);   // плитку правят
        if (sel) {   // крестик «убрать» на выбранной плитке
            textW(L"×", x + w - 14, y + 1, g.fRegular, pal::RED);
            addHit(x + w - 18, y, x + w, y + 18, [] { portRemove(); });
        }
    }
    if (rowsTotal > PT_ROWS) {
        float trackY = Y(90), trackH = PT_ROWS * (PT_H + PT_GAP) - PT_GAP;
        float thumbH = trackH * PT_ROWS / rowsTotal, thumbY = trackY + trackH * g_pl.topRow / rowsTotal;
        rectFill(X(848), trackY, X(851), trackY + trackH, rgb(20, 40, 55));
        rectFill(X(848), thumbY, X(851), thumbY + thumbH, pal::AMD);
    }

    // поле «Добавить»
    textW(L"ДОБАВИТЬ", X(14), Y(386), g.fTiny, pal::AM);
    drawFieldBox(X(14), Y(404), 200, 30, g_portBuf, g_portFocus, g.fRegular);
    addHit(X(14), Y(404), X(214), Y(434), [] { pcCommit(); g_portFocus = true; });
    // поле «Комментарий» выбранной плитки
    if (!g_pl.tiles.empty()) {
        const PortTile& t = g_pl.tiles[std::min(g_pl.sel, (int)g_pl.tiles.size() - 1)];
        std::wstring num = t.from == t.to ? std::to_wstring(t.from) : std::to_wstring(t.from) + L"-" + std::to_wstring(t.to);
        textW(L"КОММЕНТАРИЙ · " + num + L"   [F2]", X(520), Y(386), g.fTiny, pal::AM);
        std::wstring shown = g_pcFocus ? g_pcBuf
            : toW(!t.comment.empty() ? t.comment : (t.from == t.to ? portName(t.from) : ""));
        drawFieldBox(X(520), Y(404), 326, 30, shown, g_pcFocus, g.fRegular);
        addHit(X(520), Y(404), X(846), Y(434), [] { if (!g_pcFocus) pcBegin(); });
    }
    button(X(224), Y(403), 130, 32, L"+ ДОБАВИТЬ", BTN_SEC, [] { portAdd(); });
    if (!g_portMsg.empty())
        textW((g_portMsgOk ? L"✓ " : L"✕ ") + toW(g_portMsg), X(366), Y(412), g.fSmall, g_portMsgOk ? pal::GN : pal::RED, 300);
    textW(L"порт 1–65535 или диапазон «от-до» (не больше 1000 портов)", X(14), Y(444), g.fSmall, pal::STD, 480);
    if (g_pl.changes > 0) textW(L"● изменений: " + std::to_wstring(g_pl.changes), X(14), Y(464), g.fSmall, pal::AM);
    button(X(520), Y(452), 150, 32, L"ПО УМОЛЧАНИЮ", BTN_SEC, [] { portDefaults(); });
    button(X(680), Y(452), 166, 32, L"СОХРАНИТЬ", g_pl.changes > 0 ? BTN_MAIN : BTN_OFF, [] { listsSave(); });
}

static void drawLists() {
    textW(L"СПИСКИ  //  Settings\\" + std::wstring(LT_FILE[g_ltab]), X(4), Y(2), g.fRegular, pal::AM);
    // вкладки
    float tx = X(14);
    for (int i = 0; i < LT_COUNT; i++) {
        int n = i == LT_PORTS ? (int)g_pl.tiles.size() : tlItemCount(g_tl[i]);
        std::wstring name = LT_TAB[i], cntS = L" " + std::to_wstring(n) + (listChanges(i) > 0 ? L" ●" : L"");
        bool on = (i == g_ltab);
        float w = textWidth(name, g.fBold) + textWidth(cntS, g.fTiny) + 26;
        rectFill(tx, Y(30), tx + w, Y(56), on ? pal::NAVON : rgb(0, 0, 0, 0));
        rectLine(tx, Y(30), tx + w, Y(56), on ? pal::AM : pal::BOXLN);
        textW(name, tx + 13, Y(34), on ? g.fBold : g.fRegular, on ? pal::AM : pal::NAVTX);
        textW(cntS, tx + 13 + textWidth(name, g.fBold), Y(38), g.fTiny, listChanges(i) > 0 ? pal::AM : pal::STD);
        addHit(tx, Y(30), tx + w, Y(56), [i] { listsSetTab(i); });
        tx += w + 6;
    }
    if (g_ltab == LT_PORTS) drawPortsTab(); else drawTextListTab();
}

// клавиатура экрана СПИСКИ; true — клавиша обработана
static bool listsKey(WPARAM wp, bool shift, bool ctrl, bool alt) {
    if (ctrl && wp == 'V') { pasteClipboard(); return true; }
    if (ctrl && wp == 'S') { listsSave(); return true; }
    if (g_rowEditing) {
        if (wp == VK_RETURN) rowCommitEdit();
        else if (wp == VK_ESCAPE) rowCancelEdit();
        else if (wp == VK_TAB) {
            int ri = tlRowIndex();
            if (ri >= 0 && curTL().rows[ri].kind == ROW_ITEM) g_rowEditField ^= 1;
        }
        else if (wp == VK_BACK) { std::wstring* f = activeTextField(); if (f && !f->empty()) f->pop_back(); }
        return true;   // буквы приходят через WM_CHAR
    }
    if (g_ltab == LT_PORTS && g_pcFocus) {
        if (wp == VK_RETURN) pcCommit();
        else if (wp == VK_ESCAPE) g_pcFocus = false;   // отмена — комментарий не меняем
        else if (wp == VK_BACK && !g_pcBuf.empty()) g_pcBuf.pop_back();
        else if (wp == VK_TAB) return false;
        return true;
    }
    if (g_ltab == LT_PORTS && g_portFocus) {
        if (wp == VK_RETURN) portAdd();
        else if (wp == VK_ESCAPE) g_portFocus = false;
        else if (wp == VK_BACK && !g_portBuf.empty()) { g_portBuf.pop_back(); int a, b; portCheckInput(a, b); }
        else if (wp == VK_TAB) return false;
        return true;
    }
    if (wp == VK_LEFT && (ctrl || g_ltab != LT_PORTS)) { listsSetTab(g_ltab - 1); return true; }
    if (wp == VK_RIGHT && (ctrl || g_ltab != LT_PORTS)) { listsSetTab(g_ltab + 1); return true; }
    if (g_ltab == LT_PORTS) {
        int n = (int)g_pl.tiles.size();
        if (wp == VK_LEFT && n)  g_pl.sel = std::max(0, g_pl.sel - 1);
        else if (wp == VK_RIGHT && n) g_pl.sel = std::min(n - 1, g_pl.sel + 1);
        else if (wp == VK_UP && n)   portMoveVert(-1);
        else if (wp == VK_DOWN && n) portMoveVert(+1);
        else if (wp == VK_DELETE) portRemove();
        else if (wp == VK_RETURN || wp == VK_INSERT) g_portFocus = true;
        else if (wp == VK_F2) pcBegin();
        else return false;
        portEnsureVisible();
        return true;
    }
    TextList& L = curTL();
    int n = (int)tlVisible(L).size();
    if (alt && wp == VK_UP)   { rowMove(-1); return true; }
    if (alt && wp == VK_DOWN) { rowMove(+1); return true; }
    if (wp == VK_UP)          tlSelect(L.sel - 1);
    else if (wp == VK_DOWN)   tlSelect(L.sel + 1);
    else if (wp == VK_PRIOR)  tlSelect(L.sel - TL_ROWS);
    else if (wp == VK_NEXT)   tlSelect(L.sel + TL_ROWS);
    else if (wp == VK_HOME)   tlSelect(0);
    else if (wp == VK_END)    tlSelect(n - 1);
    else if (wp == VK_RETURN || wp == VK_F2) rowBeginEdit();
    else if (wp == VK_INSERT) rowInsert(ROW_ITEM);
    else if (wp == VK_DELETE) rowDelete();
    else return false;
    (void)shift;
    return true;
}
// ввод символов в поля списков
static bool listsChar(wchar_t c) {
    if (g.screen != SCR_LISTS) return false;
    if (g_rowEditing) {
        std::wstring* f = activeTextField();
        if (f && c >= 32 && c != 127 && f->size() < 200) f->push_back(c);
        return true;
    }
    if (g_ltab == LT_PORTS && g_pcFocus) {
        if (c >= 32 && c != 127 && g_pcBuf.size() < 100) g_pcBuf.push_back(c);
        return true;
    }
    if (g_ltab == LT_PORTS) {
        bool okc = (c >= L'0' && c <= L'9') || c == L'-';
        if (okc && g_portBuf.size() < 11) {
            g_portFocus = true;   // начал печатать цифры — сразу в поле «Добавить»
            g_portBuf.push_back(c);
            int a, b; portCheckInput(a, b);
            return true;
        }
    }
    return false;
}
// двойной клик по строке — правка
static void listsDblClick() {
    if (g.screen == SCR_LISTS && g_ltab == LT_PORTS) {   // двойной клик по плитке — правка комментария
        if (g.mouseX >= X(14) && g.mouseX <= X(846) && g.mouseY >= Y(90) && g.mouseY <= Y(90 + PT_ROWS * (PT_H + PT_GAP)))
            pcBegin();
        return;
    }
    if (g.screen != SCR_LISTS || g_rowEditing) return;
    float ry = (float)g.mouseY - Y(94);
    if (g.mouseX < X(18) || g.mouseX > X(590) || ry < 0) return;
    int k = (int)(ry / TL_ROWH);
    if (k >= TL_ROWS) return;
    int vi = curTL().top + k;
    if (vi < (int)tlVisible(curTL()).size()) { tlSelect(vi); rowBeginEdit(); }
}

// ===================== КАРКАС: МЕНЮ, ПЕРЕКЛЮЧЕНИЕ, РИСОВАНИЕ =====================
static RECT navRect(int i) {
    RECT r; r.left = 34; r.right = 198; r.top = 96 + i * 46; r.bottom = r.top + 36; return r;
}
static void drawSidebar() {
    for (int i = 0; i < SCR_COUNT; i++) {
        RECT r = navRect(i);
        bool on = (i == g.screen);
        if (on) {
            rectFill((float)r.left, (float)r.top, (float)r.right, (float)r.bottom, pal::NAVON);
            rectLine((float)r.left, (float)r.top, (float)r.right, (float)r.bottom, pal::AMD);
            rectFill((float)r.left, (float)r.top, r.left + 4.0f, (float)r.bottom, pal::AM);
        }
        textW(NAV[i], r.left + 18.0f, r.top + 8.0f, on ? g.fBold : g.fRegular, on ? pal::TX : pal::NAVTX);
        // янтарная точка справа — в этом разделе сейчас идёт проверка
        if (screenBusy(i)) textW(L"●", r.right - 22.0f, r.top + 8.0f, g.fRegular, pal::AM);
        addHit((float)r.left, (float)r.top, (float)r.right, (float)r.bottom, [i] { setScreen(i); });
    }
    line(214, 90, 214, WIN_H - 60.0f, pal::GRID);
}

static void setScreen(int s) {
    if (g.screen == SCR_SETTINGS) commitEdit();
    if (g.screen == SCR_LISTS) { rowCommitEdit(); pcCommit(); g_portFocus = false; }
    if (s == SCR_LISTS) listsEnsureLoaded();
    g_drag = -1;
    g.screen = s;
    bool have; { std::lock_guard<std::mutex> lk(g_stMx); have = g_st.have; }
    if (s == SCR_HOME && (!have || GetTickCount64() - g_stTick > 15000)) refreshStatus();
    if (s == SCR_HOME || s == SCR_REPORTS) g_reportsDirty = true;
    if (s == SCR_SETTINGS && !setDirty()) g_edit = g_config;   // свежая копия, если не было правок
    if (s == SCR_REPORTS) repResync();
    InvalidateRect(g.hwnd, nullptr, FALSE);
}

static const wchar_t* footerFor(int s) {
    switch (s) {
        case SCR_HOME:     return L"[1-5] быстрый запуск   [F5] обновить состояние   [Tab] раздел   [Esc] выход";
        case SCR_REPORTS:  return L"[↑↓] отчёт   [←→] фильтр   [Enter] открыть   [Del] удалить   [Tab] раздел   [Esc] выход";
        case SCR_LISTS:    return g_ltab == LT_PORTS
                               ? L"[←→↑↓] порт   [F2] комментарий   [Del] убрать   [цифры] добавить   [Ctrl+←→] вкладка   [Ctrl+S] сохранить"
                               : L"[↑↓] строка   [Enter] править   [Ins] добавить   [Del] удалить   [Alt+↑↓] переместить   [←→] вкладка";
        case SCR_SETTINGS: return L"[↑↓] параметр   [←→] изменить (Shift ×10)   [Enter] ввести число   [Ctrl+S] сохранить   [Tab] раздел";
        default:           return L"[Enter] запустить   [↑↓/Tab] раздел   [колесо] прокрутка   [Esc] выход";
    }
}

static void drawContent() {
    rectFill(LPX, LPY, LPX + LPW, LPY + LPH, pal::PANEL);
    bracket(LPX - 8, LPY - 2, 0, pal::AMD);
    bracket(LPX + LPW + 8, LPY - 2, 1, pal::AMD);
    bracket(LPX - 8, LPY + LPH + 2, 2, pal::AMD);
    bracket(LPX + LPW + 8, LPY + LPH + 2, 3, pal::AMD);
    if (screenRunnable(g.screen))      drawRunScreen();
    else if (g.screen == SCR_HOME)     drawHome();
    else if (g.screen == SCR_REPORTS)  drawReports();
    else if (g.screen == SCR_LISTS)    drawLists();
    else if (g.screen == SCR_SETTINGS) drawSettings();
}

static void render() {
    ensureRenderTarget();
    if (!g.rt) return;
    if (!g_brush) g.rt->CreateSolidColorBrush(pal::TX, &g_brush);
    g_hits.clear();
    g.rt->BeginDraw();
    g.rt->SetTransform(D2D1::Matrix3x2F::Identity());
    drawBackground();
    drawHeader();
    drawSidebar();
    drawContent();
    drawFooter(footerFor(g.screen));
    HRESULT hr = g.rt->EndDraw();
    if (hr == D2DERR_RECREATE_TARGET) { safeRelease(g_brush); safeRelease(g.rt); }
}

// ===================== КЛАВИАТУРА =====================
static void onKey(WPARAM wp) {
    bool shift = GetKeyState(VK_SHIFT) < 0, ctrl = GetKeyState(VK_CONTROL) < 0;

    // ввод числа в настройках перехватывает клавиши
    if (g_editField >= 0) {
        if (wp == VK_RETURN) commitEdit();
        else if (wp == VK_ESCAPE) cancelEdit();
        else if (wp == VK_BACK && !g_editBuf.empty()) g_editBuf.pop_back();
        return;   // цифры приходят через WM_CHAR
    }
    if (g.screen == SCR_LISTS && listsKey(wp, shift, ctrl, false)) return;
    if (wp == VK_ESCAPE) { PostMessage(g.hwnd, WM_CLOSE, 0, 0); return; }
    if (wp == VK_TAB) { setScreen((g.screen + (shift ? SCR_COUNT - 1 : 1)) % SCR_COUNT); return; }
    if (ctrl && wp == 'S' && g.screen == SCR_SETTINGS) { saveSettings(); return; }

    switch (g.screen) {
    case SCR_HOME:
        if (wp >= '1' && wp <= '5') { int s = SCR_SITES + (int)(wp - '1'); if (screenBusy(s)) setScreen(s); else startRun(s); }
        else if (wp >= VK_NUMPAD1 && wp <= VK_NUMPAD5) { int s = SCR_SITES + (int)(wp - VK_NUMPAD1); if (screenBusy(s)) setScreen(s); else startRun(s); }
        else if (wp == VK_F5) refreshStatus();
        else if (wp == VK_UP)   setScreen((g.screen + SCR_COUNT - 1) % SCR_COUNT);
        else if (wp == VK_DOWN) setScreen((g.screen + 1) % SCR_COUNT);
        break;
    case SCR_REPORTS: {
        int n = (int)repFiltered().size();
        if (wp == VK_UP) repSelect(g_repSel - 1);
        else if (wp == VK_DOWN) repSelect(g_repSel + 1);
        else if (wp == VK_PRIOR) repSelect(g_repSel - REP_ROWS);
        else if (wp == VK_NEXT) repSelect(g_repSel + REP_ROWS);
        else if (wp == VK_HOME) repSelect(0);
        else if (wp == VK_END) repSelect(n - 1);
        else if (wp == VK_LEFT)  { g_repFilter = (g_repFilter + 5) % 6; g_repTop = 0; repSelect(0); }
        else if (wp == VK_RIGHT) { g_repFilter = (g_repFilter + 1) % 6; g_repTop = 0; repSelect(0); }
        else if (wp == VK_RETURN) repOpenExternal();
        else if (wp == VK_DELETE) repDelete();
        else if (wp == VK_F5) { scanReports(); repResync(); }
        break;
    }
    case SCR_SETTINGS:
        if (wp == VK_UP)   g_setSel = (g_setSel + SET_ROWS - 1) % SET_ROWS;
        else if (wp == VK_DOWN) g_setSel = (g_setSel + 1) % SET_ROWS;
        else if ((wp == VK_LEFT || wp == VK_RIGHT) && g_setSel < 5) {
            int dir = (wp == VK_RIGHT) ? 1 : -1;
            setParam(g_setSel, g_edit.*(PARAMS[g_setSel].ptr) + dir * PARAMS[g_setSel].step * (shift ? 10 : 1));
        }
        else if (wp == VK_SPACE && g_setSel == 5) toggleSocksAuto();
        else if (wp == VK_RETURN) {
            if (g_setSel < 5) beginEdit(g_setSel);
            else if (g_edit.SocksPort > 0) beginEdit(5);
            else toggleSocksAuto();
        }
        break;
    default:   // разделы с проверками
        if (wp == VK_RETURN) startRun(g.screen);
        else if (wp == VK_UP)   setScreen((g.screen + SCR_COUNT - 1) % SCR_COUNT);
        else if (wp == VK_DOWN) setScreen((g.screen + 1) % SCR_COUNT);
        break;
    }
}

// ----- обработка окна -----
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE:
        SetTimer(h, 1, 100, nullptr);
        return 0;
    case WM_SIZE:
        if (g.rt) g.rt->Resize(D2D1::SizeU(LOWORD(lp), HIWORD(lp)));
        return 0;
    case WM_TIMER: {
        static int ticks = 0;
        bool redraw = g_dirty.exchange(false);
        if (g_reportsDirty.exchange(false)) {   // появился/пропал отчёт — пересканировать
            scanReports();
            if (g.screen == SCR_REPORTS) repResync();
            redraw = true;
        }
        if (++ticks % 10 == 0) redraw = true;   // раз в секунду: часы, таймер «точно удалить?»
        if (redraw) InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps; BeginPaint(h, &ps);
        render();
        EndPaint(h, &ps);
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int d = GET_WHEEL_DELTA_WPARAM(wp) / 120;
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        ScreenToClient(h, &pt);   // колесо даёт экранные координаты
        if (screenRunnable(g.screen)) {
            std::lock_guard<std::mutex> lk(g_logMx);
            ScreenLog& S = g_logs[g.screen];
            S.follow = false; S.scroll -= d * 3;
        } else if (g.screen == SCR_LISTS) {
            if (g_ltab == LT_PORTS) g_pl.topRow = std::max(0, g_pl.topRow - d);
            else {
                TextList& L = curTL();
                int n = (int)tlVisible(L).size();
                L.top = std::max(0, std::min(L.top - d * 3, std::max(0, n - TL_ROWS)));
            }
        } else if (g.screen == SCR_REPORTS) {
            if (pt.x < X(400)) {   // над списком
                int n = (int)repFiltered().size();
                g_repTop = std::max(0, std::min(g_repTop - d * 3, std::max(0, n - REP_ROWS)));
            } else {               // над просмотром
                g_prevTop = std::max(0, g_prevTop - d * 3);
            }
        }
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_KEYDOWN:
        onKey(wp);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_SYSKEYDOWN:
        if (g.screen == SCR_LISTS && (wp == VK_UP || wp == VK_DOWN)) {
            listsKey(wp, false, false, true);
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        break;   // остальное (Alt+F4 и т.п.) — системе
    case WM_LBUTTONDBLCLK:
        g.mouseX = GET_X_LPARAM(lp); g.mouseY = GET_Y_LPARAM(lp);
        listsDblClick();
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    case WM_CHAR:
        if (listsChar((wchar_t)wp)) { InvalidateRect(h, nullptr, FALSE); return 0; }
        // цифры в поле ввода настроек
        if (g_editField >= 0 && wp >= L'0' && wp <= L'9' && g_editBuf.size() < 6) {
            g_editBuf.push_back((wchar_t)wp);
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        g.mouseX = GET_X_LPARAM(lp); g.mouseY = GET_Y_LPARAM(lp);
        auto hits = g_hits;   // копия: обработчик клика может поменять экран
        bool hitAny = false;
        for (auto it = hits.rbegin(); it != hits.rend(); ++it) {   // сверху вниз: последние нарисованы поверх
            const D2D1_RECT_F& r = it->r;
            if (g.mouseX >= r.left && g.mouseX <= r.right && g.mouseY >= r.top && g.mouseY <= r.bottom) {
                it->fn();
                hitAny = true;
                break;
            }
        }
        // клик в пустое место — применить набранное число
        if (!hitAny && g_editField >= 0) commitEdit();
        if (!hitAny && g_rowEditing) rowCommitEdit();
        if (!hitAny) { g_portFocus = false; pcCommit(); }
        if (g_drag >= 0) SetCapture(h);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_MOUSEMOVE:
        g.mouseX = GET_X_LPARAM(lp); g.mouseY = GET_Y_LPARAM(lp);
        if (g_drag >= 0) { sliderFromMouse(g_drag); InvalidateRect(h, nullptr, FALSE); }
        return 0;
    case WM_LBUTTONUP:
        if (g_drag >= 0) { g_drag = -1; ReleaseCapture(); }
        return 0;
    case WM_DESTROY:
        KillTimer(h, 1);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    ensureAdmin();
    if (!lagInit()) { MessageBoxW(nullptr, L"Ошибка инициализации Winsock.", L"Лаг", MB_ICONERROR); return 1; }
    g.admin = isAdmin();
    g_guiMode = true;
    g_edit = g_config;

    createDeviceIndependent();

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.style = CS_DBLCLKS;   // двойной клик (правка строки в списках)
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"LagWindow";
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(1));
    RegisterClassW(&wc);

    DWORD style = (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX);  // фикс. размер
    RECT rc{ 0, 0, WIN_W, WIN_H };
    AdjustWindowRect(&rc, style, FALSE);
    g.hwnd = CreateWindowW(L"LagWindow", L"Лаг — диагностика сети", style,
        CW_USEDEFAULT, CW_USEDEFAULT, rc.right - rc.left, rc.bottom - rc.top,
        nullptr, nullptr, hInst, nullptr);
    if (!g.hwnd) return 1;

    // тёмный заголовок окна (Windows 10/11)
    BOOL dark = TRUE;
    DwmSetWindowAttribute(g.hwnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof(dark));

    scanReports();
    refreshStatus();   // плитки главной заполняются в фоне

    ShowWindow(g.hwnd, nShow);
    UpdateWindow(g.hwnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // окно закрыли, а фоновые потоки ещё работают —
    // завершаемся сразу, без деструкторов, чтобы не упасть на выходе
    if (anyBusy() || g_bg > 0) TerminateProcess(GetCurrentProcess(), 0);

    safeRelease(g_brush);
    safeRelease(g.rt);
    discardDeviceIndependent();
    WSACleanup();
    return (int)msg.wParam;
}
