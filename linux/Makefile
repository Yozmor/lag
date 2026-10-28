# Makefile — сборка Lag для Linux.
# Нужны: g++ (C++17) и заголовки OpenSSL.
#   Debian/Ubuntu: sudo apt install build-essential libssl-dev
#   Fedora:        sudo dnf install gcc-c++ make openssl-devel
#   Arch:          sudo pacman -S base-devel openssl
#
#   make            собрать ./lag
#   make install    скопировать в ~/.local/bin (или PREFIX)
#   make clean      убрать сборку

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wno-unused-function
LDLIBS    = -lssl -lcrypto -lpthread
PREFIX   ?= $(HOME)/.local

lag: lag.cpp lag_core.cpp lag_probe.cpp lag_tui.cpp
	$(CXX) $(CXXFLAGS) lag.cpp -o lag $(LDLIBS)

install: lag
	install -Dm755 lag $(PREFIX)/bin/lag
	@echo "Установлено в $(PREFIX)/bin/lag"
	@echo "Для трассировки без root выдай NextTrace права один раз:"
	@echo "  sudo setcap cap_net_raw,cap_net_admin+eip <папка данных>/Tools/nexttrace"

clean:
	rm -f lag

.PHONY: install clean
