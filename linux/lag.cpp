// lag.cpp — точка входа Lag для Linux. Собирает три модуля в одну программу.
// Сборка: make  (нужны g++ C++17 и libssl-dev / openssl-devel).
#include "lag_core.cpp"
#include "lag_probe.cpp"
#include "lag_tui.cpp"

static void usage() {
    printf("Lag %s — диагностика сети и обхода блокировок (Linux)\n\n", SCRIPT_VERSION.c_str());
    printf("Использование:\n");
    printf("  lag                 запустить терминальный интерфейс\n");
    printf("  lag --run <раздел>  выполнить проверку без интерфейса (для cron/скриптов)\n");
    printf("  lag --version       версия\n");
    printf("  lag --help          эта справка\n\n");
    printf("Разделы: sites  dns  zond  trace  ports  net  (или all)\n\n");
    printf("Данные (списки, логи, config.json) — рядом с программой либо в ~/.local/share/lag,\n");
    printf("если папка программы недоступна для записи.\n");
}

int main(int argc, char** argv) {
    SSL_library_init();
    lagInit();
    std::vector<std::string> a(argv + 1, argv + argc);
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i] == "--version" || a[i] == "-v") { printf("Lag %s\n", SCRIPT_VERSION.c_str()); return 0; }
        if (a[i] == "--help" || a[i] == "-h")    { usage(); return 0; }
        if (a[i] == "--run") {
            if (i + 1 >= a.size()) { fprintf(stderr, "Укажи раздел: lag --run sites\n"); return 2; }
            return headlessRun(normSection(a[i + 1]));
        }
        fprintf(stderr, "Неизвестный аргумент: %s (см. lag --help)\n", a[i].c_str());
        return 2;
    }
    return tuiMain();
}
