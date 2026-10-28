<h1 align="center">Лаг — Linux</h1>

Терминальная версия (TUI). Тот же движок диагностики, что в Windows-версии; системные части написаны под Linux.

## Установка одной командой

**1. Зависимости** — один раз, под свой дистрибутив (git, компилятор C++17, заголовки OpenSSL):

```bash
sudo apt install -y git build-essential libssl-dev     # Debian / Ubuntu
sudo dnf install -y git gcc-c++ make openssl-devel      # Fedora
sudo pacman -S --needed git base-devel openssl          # Arch
```

**2. Скачать, собрать и поставить как команду `lag`:**

```bash
git clone https://github.com/Yozmor/lagg.git && cd lagg/linux && make && sudo make install PREFIX=/usr/local
```

После этого просто набирай **`lag`** в любом терминале.

Без `sudo` (установка в домашнюю папку `~/.local/bin`):

```bash
git clone https://github.com/Yozmor/lagg.git && cd lagg/linux && make install
```

Если после этого `lag` не находится — `~/.local/bin` не в `PATH`; `make install` подскажет, какую строку добавить в `~/.bashrc` (или поставь командой с `sudo` выше).

Без `git` (скачать архивом):

```bash
curl -L https://github.com/Yozmor/lagg/archive/refs/heads/main.tar.gz | tar xz && cd lagg-main/linux && make && sudo make install PREFIX=/usr/local
```

Обновлять потом можно прямо из программы (раздел «Обновление») или повторив команду.

## Запуск

```bash
lag                  # терминальный интерфейс
lag --help           # справка
```

Если не ставил в систему, а только собрал (`make`) — запускай из папки: `./lag`.

## Интерфейс

- **↑↓** — выбрать пункт меню; **Tab** — переключить фокус меню / окно.
- **Enter** — запустить проверку / открыть; **1–8** — быстрый запуск раздела.
- В разделе: **↑↓** листают лог, **Enter** перезапускает; в «Настройках» **←→** меняют значение, **S** сохраняет.
- **Esc** — на главную; **Q** или **0** — выход.

Окну нужно хотя бы 80×20; на маленьком терминале Lag попросит увеличить окно.

### Без интерфейса (cron, скрипты)

```bash
lag --run sites      # разделы: sites dns zond trace ports net  (или all)
lag --run all
```

Печатает отчёт в консоль и сохраняет его в `Logs/` — удобно вешать на расписание.

## Данные

Списки, логи и `config.json` лежат рядом с программой; если её папка недоступна для записи (например, установлена в `/usr/local/bin`) — в `~/.local/share/lag`.

При первом запуске списки заполняются примерами, правь под себя: `Settings/sites.txt`, `dns_targets.txt`, `trace_targets.txt`, `scan_targets.txt`, `ports.txt`. Таблица настроек — та же, что в Windows-версии (см. корневой `windows/README.md`).

## Трассировка

Использует [NextTrace](https://github.com/nxtrace/NTrace-core) — скачивается автоматически в `Tools/` под твою архитектуру. Для «сырых» сокетов нужны права. Либо запускай `sudo lag`, либо один раз выдай права самому NextTrace:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip <папка данных>/Tools/nexttrace
```

Путь к папке данных Lag показывает в разделе «Сеть / VPN» и в начале отчётов.

## Определение VPN

- **Прокси** — берётся из переменных окружения (`https_proxy`/`all_proxy`), настроек GNOME (`gsettings`) или KDE (`kioslaverc`).
- **Туннель (TUN)** — по тому, кто владеет маршрутом по умолчанию: сплит `0.0.0.0/1` (подпись sing-box/WireGuard/v2rayTun), полный дефолт на tun-интерфейсе или policy-routing. Просто поднятый tun, который ведёт только свою сеть (Yggdrasil), за VPN не считается.

## Файлы

| Файл | Что это |
|---|---|
| `lag.cpp` | Точка входа, разбор аргументов |
| `lag_core.cpp` | Ядро: проверки, отчёты, сеть, HTTPS (OpenSSL), обновление |
| `lag_probe.cpp` | ЗОНД: TLS-проба, DoH, тест обхода, UDP/STUN, NAT |
| `lag_tui.cpp` | Терминальный интерфейс + режим `--run` |
| `Makefile` | Сборка |
