# Makefile — сборка Lag для Linux.
# Нужны: g++ (C++17) и заголовки OpenSSL.
#   Debian/Ubuntu: sudo apt install build-essential libssl-dev
#   Fedora:        sudo dnf install gcc-c++ make openssl-devel
#   Arch:          sudo pacman -S base-devel openssl
#
#   make                  собрать ./lag
#   make install          поставить как команду lag (в ~/.local/bin по умолчанию)
#   sudo make install PREFIX=/usr/local   поставить для всех (всегда в PATH)
#   make uninstall        удалить
#   make clean            убрать сборку

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wno-unused-function
LDLIBS    = -lssl -lcrypto -lpthread
PREFIX   ?= $(HOME)/.local
BINDIR    = $(DESTDIR)$(PREFIX)/bin

lag: lag.cpp lag_core.cpp lag_probe.cpp lag_tui.cpp
	$(CXX) $(CXXFLAGS) lag.cpp -o lag $(LDLIBS)

install: lag
	install -Dm755 lag $(BINDIR)/lag
	@echo ""
	@echo "Установлено: $(PREFIX)/bin/lag"
	@case ":$$PATH:" in \
	  *":$(PREFIX)/bin:"*) echo "Готово — запускай командой:  lag" ;; \
	  *) echo "ВНИМАНИЕ: $(PREFIX)/bin не в PATH. Добавь строку в ~/.bashrc и открой новый терминал:"; \
	     echo "  export PATH=\"$(PREFIX)/bin:\$$PATH\""; \
	     echo "или ставь для всех:  sudo make install PREFIX=/usr/local" ;; \
	esac
	@echo "Трассировка без root — один раз выдай права NextTrace (путь Lag покажет в разделе «Сеть / VPN»):"
	@echo "  sudo setcap cap_net_raw,cap_net_admin+eip ~/.local/share/lag/Tools/nexttrace"

uninstall:
	rm -f $(BINDIR)/lag
	@echo "Удалено: $(PREFIX)/bin/lag  (данные в ~/.local/share/lag остались)"

clean:
	rm -f lag

.PHONY: install uninstall clean
