// lag_probe.cpp — ЗОНД для Linux: SNI-проба + классификация состояния TLS-соединения,
// DoH, тест обхода (фрагментация), UDP/STUN и тип NAT. Тот же код, что windows/LagProbe.cpp;
// Winsock закрыт прослойкой совместимости в lag_core.cpp.
// Отвечает на главный вопрос адаптации: «что именно режется» — IP, SNI, или встаёт и умирает.
//
// ВКЛЮЧАЕТСЯ ПОСЛЕ lag_core.cpp (lag.cpp включает оба). Это не отдельная единица компиляции,
// а продолжение той же: модуль пользуется функциями ядра (connectTcp, resolveIPv4, dnsQueryA,
// writeLog, toU8, трим/таблицы, jStr, g_config). Отдельно не компилировать.
//
// Что делает:
//   1) собирает настоящий TLS ClientHello с нужным SNI и шлёт его на IP:443;
//   2) по реакции классифицирует: не встало TCP / RST после ClientHello / тишина (дроп) / пришёл ответ;
//   3) сверяет реальный SNI с «чистым» (заведомо разрешённым) на том же IP и выдаёт вердикт.
//
// Проба открывает настоящие TLS-соединения к целям — это обычный трафик, как у браузера.

// ================== TLS ClientHello ВРУЧНУЮ ==================
// Минимальный, но валидный ClientHello (TLS 1.2/1.3), на который настоящий сервер отвечает
// ServerHello. DPI смотрит SNI независимо от того, завершилось бы рукопожатие.

static void tlsU8 (std::vector<uint8_t>& v, uint8_t x)  { v.push_back(x); }
static void tlsU16(std::vector<uint8_t>& v, uint16_t x) { v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)(x & 0xFF)); }
static void tlsBytes(std::vector<uint8_t>& v, const uint8_t* p, int n) { v.insert(v.end(), p, p + n); }

// псевдослучайные байты (random, session_id, key_share) — не криптография, для пробы достаточно
static void fillRandom(uint8_t* p, int n) {
    static bool seeded = false;
    if (!seeded) { srand((unsigned)(GetTickCount64() ^ (uintptr_t)p)); seeded = true; }
    for (int i = 0; i < n; i++) p[i] = (uint8_t)(rand() & 0xFF);
}

static std::vector<uint8_t> buildClientHello(const std::string& sni) {
    std::vector<uint8_t> ext;

    // server_name (0x0000) — ради него всё и затевается
    {
        std::vector<uint8_t> entry;
        tlsU8(entry, 0x00);                         // name_type = host_name
        tlsU16(entry, (uint16_t)sni.size());
        tlsBytes(entry, (const uint8_t*)sni.data(), (int)sni.size());
        std::vector<uint8_t> body;
        tlsU16(body, (uint16_t)entry.size());       // server_name_list length
        body.insert(body.end(), entry.begin(), entry.end());
        tlsU16(ext, 0x0000); tlsU16(ext, (uint16_t)body.size());
        ext.insert(ext.end(), body.begin(), body.end());
    }
    // supported_groups (0x000a): x25519, secp256r1
    {
        std::vector<uint8_t> g; tlsU16(g, 4); tlsU16(g, 0x001d); tlsU16(g, 0x0017);
        tlsU16(ext, 0x000a); tlsU16(ext, (uint16_t)g.size()); ext.insert(ext.end(), g.begin(), g.end());
    }
    // ec_point_formats (0x000b): uncompressed
    {
        std::vector<uint8_t> f; tlsU8(f, 1); tlsU8(f, 0x00);
        tlsU16(ext, 0x000b); tlsU16(ext, (uint16_t)f.size()); ext.insert(ext.end(), f.begin(), f.end());
    }
    // signature_algorithms (0x000d)
    {
        static const uint16_t algs[] = { 0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601 };
        std::vector<uint8_t> s; tlsU16(s, (uint16_t)sizeof(algs));
        for (uint16_t a : algs) tlsU16(s, a);
        tlsU16(ext, 0x000d); tlsU16(ext, (uint16_t)s.size()); ext.insert(ext.end(), s.begin(), s.end());
    }
    // supported_versions (0x002b): TLS1.3, TLS1.2  (список с 1-байтовой длиной)
    {
        std::vector<uint8_t> v; tlsU8(v, 4); tlsU16(v, 0x0304); tlsU16(v, 0x0303);
        tlsU16(ext, 0x002b); tlsU16(ext, (uint16_t)v.size()); ext.insert(ext.end(), v.begin(), v.end());
    }
    // key_share (0x0033): x25519 с псевдослучайным ключом — чтобы ответил и TLS1.3-сервер
    {
        uint8_t key[32]; fillRandom(key, 32);
        std::vector<uint8_t> share; tlsU16(share, 0x001d); tlsU16(share, 32); tlsBytes(share, key, 32);
        std::vector<uint8_t> body; tlsU16(body, (uint16_t)share.size());
        body.insert(body.end(), share.begin(), share.end());
        tlsU16(ext, 0x0033); tlsU16(ext, (uint16_t)body.size()); ext.insert(ext.end(), body.begin(), body.end());
    }

    // тело ClientHello
    std::vector<uint8_t> ch;
    tlsU16(ch, 0x0303);                             // client_version TLS1.2
    uint8_t rnd[32]; fillRandom(rnd, 32); tlsBytes(ch, rnd, 32);   // random
    uint8_t sid[32]; fillRandom(sid, 32);
    tlsU8(ch, 32); tlsBytes(ch, sid, 32);           // session_id
    static const uint16_t suites[] = {
        0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,0xcca9,0xcca8,0x009e,0x009c
    };
    tlsU16(ch, (uint16_t)sizeof(suites));
    for (uint16_t c : suites) tlsU16(ch, c);
    tlsU8(ch, 1); tlsU8(ch, 0x00);                  // compression_methods: null
    tlsU16(ch, (uint16_t)ext.size());
    ch.insert(ch.end(), ext.begin(), ext.end());

    // handshake header (тип + 3-байтовая длина)
    std::vector<uint8_t> hs;
    tlsU8(hs, 0x01);
    tlsU8(hs, (uint8_t)((ch.size() >> 16) & 0xFF));
    tlsU8(hs, (uint8_t)((ch.size() >> 8) & 0xFF));
    tlsU8(hs, (uint8_t)(ch.size() & 0xFF));
    hs.insert(hs.end(), ch.begin(), ch.end());

    // record header
    std::vector<uint8_t> rec;
    tlsU8(rec, 0x16);                               // handshake
    tlsU16(rec, 0x0301);                            // версия записи TLS1.0 (для совместимости)
    tlsU16(rec, (uint16_t)hs.size());
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

// ================== ПРОБА ОДНОГО TLS-СОЕДИНЕНИЯ ==================
// Это и есть «детект зависания»: различаем четыре исхода по реакции на ClientHello.
enum class TlsOutcome { NoConnect, Reset, Stall, Answered };

struct TlsProbe {
    TlsOutcome outcome = TlsOutcome::NoConnect;
    long connectMs = -1, replyMs = -1;
    int  bytesBack = 0;
    bool tlsReply = false;      // ответ начинается с TLS-записи (0x16 ServerHello / 0x15 alert)
    std::string note;
};

static TlsProbe probeTls(const std::string& ip, const std::string& sni, int timeoutMs) {
    TlsProbe pr;
    auto t0 = std::chrono::steady_clock::now();
    SOCKET s = connectTcp(ip, 443, timeoutMs);      // блокирующий сокет с таймаутами recv/send (из ядра)
    pr.connectMs = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    if (s == INVALID_SOCKET) { pr.outcome = TlsOutcome::NoConnect; pr.note = "TCP не встал"; return pr; }

    std::vector<uint8_t> hello = buildClientHello(sni);
    int off = 0;
    while (off < (int)hello.size()) {
        int w = send(s, (const char*)hello.data() + off, (int)hello.size() - off, 0);
        if (w <= 0) { pr.outcome = TlsOutcome::Reset; pr.note = "обрыв при отправке ClientHello"; closesocket(s); return pr; }
        off += w;
    }

    auto t1 = std::chrono::steady_clock::now();
    unsigned char buf[1024];
    int n = recv(s, (char*)buf, sizeof(buf), 0);    // ждёт ответ до timeoutMs (SO_RCVTIMEO стоит в connectTcp)
    pr.replyMs = (long)std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - t1).count();

    if (n > 0) {
        pr.bytesBack = n;
        pr.tlsReply  = (buf[0] == 0x16 || buf[0] == 0x15);
        pr.outcome   = TlsOutcome::Answered;
        pr.note = (buf[0] == 0x16) ? "ServerHello"
                : (buf[0] == 0x15) ? "TLS alert (хост ответил)"
                                   : "данные не TLS (возможно заглушка)";
    } else if (n == 0) {
        pr.outcome = TlsOutcome::Reset; pr.note = "закрыто без ответа (FIN)";
    } else {
        int e = WSAGetLastError();
        if      (e == WSAECONNRESET) { pr.outcome = TlsOutcome::Reset; pr.note = "RST после ClientHello"; }
        else if (e == WSAETIMEDOUT)  { pr.outcome = TlsOutcome::Stall; pr.note = "тишина (таймаут)"; }
        else                         { pr.outcome = TlsOutcome::Stall; pr.note = "recv ошибка " + std::to_string(e); }
    }
    closesocket(s);
    return pr;
}

// ================== ДОВЕРЕННЫЙ DNS ЧЕРЕЗ DoH ==================
// Обычный UDP к 8.8.8.8 в РФ подменяют на лету, поэтому доверенный IP берём через DNS-over-HTTPS:
// запрос идёт внутри TLS, перехватить его так же просто нельзя. Эндпоинты пробуются по очереди;
// варианты «по IP» не отправляют SNI, поэтому переживают фильтрацию по имени dns.google.
static const char* DOH_ENDPOINTS[] = {
    "https://dns.google/resolve?name={d}&type=A",
    "https://1.1.1.1/dns-query?name={d}&type=A&ct=application/dns-json",
    "https://8.8.8.8/resolve?name={d}&type=A",
};

static bool looksIPv4s(const std::string& s) {
    int dots = 0; if (s.empty()) return false;
    for (char c : s) { if (c == '.') dots++; else if (c < '0' || c > '9') return false; }
    return dots == 3;
}
// DoH-запрос A-записи. Возвращает первый IPv4 или "".
static std::string dohQueryA(const std::string& fmt, const std::string& domain, int timeoutMs) {
    std::string url = fmt;
    size_t p = url.find("{d}");
    if (p != std::string::npos) url.replace(p, 3, domain);
    int sec = std::max(1, timeoutMs / 1000);
    HttpResult r = httpRequest(url, "GET", sec, false, "", true);   // напрямую, с телом ответа
    if (!r.ok || r.body.empty()) return "";
    // ответ JSON: ... "Answer":[{"name":..,"type":1,"TTL":..,"data":"1.2.3.4"}, ..]
    std::regex re("\"type\"\\s*:\\s*1\\b[^}]*?\"data\"\\s*:\\s*\"([0-9.]+)\"");
    for (auto it = std::sregex_iterator(r.body.begin(), r.body.end(), re);
         it != std::sregex_iterator(); ++it) {
        std::string ip = (*it)[1];
        if (looksIPv4s(ip)) return ip;
    }
    return "";
}
// DoH-запрос ВСЕХ A-записей (мульти-IP: у сервиса обычно несколько адресов, часть может быть прибита).
static std::vector<std::string> dohQueryAll(const std::string& fmt, const std::string& domain, int timeoutMs) {
    std::vector<std::string> ips;
    std::string url = fmt; size_t p = url.find("{d}");
    if (p != std::string::npos) url.replace(p, 3, domain);
    int sec = std::max(1, timeoutMs / 1000);
    HttpResult r = httpRequest(url, "GET", sec, false, "", true);
    if (!r.ok || r.body.empty()) return ips;
    std::regex re("\"type\"\\s*:\\s*1\\b[^}]*?\"data\"\\s*:\\s*\"([0-9.]+)\"");
    for (auto it = std::sregex_iterator(r.body.begin(), r.body.end(), re);
         it != std::sregex_iterator(); ++it) {
        std::string ip = (*it)[1];
        if (!looksIPv4s(ip)) continue;
        bool dup = false; for (auto& e : ips) if (e == ip) { dup = true; break; }
        if (!dup) ips.push_back(ip);
    }
    return ips;
}
// Выбрать рабочий DoH-эндпоинт (который доходит из этой сети). "" — ни один не ответил.
static std::string pickDoh(int timeoutMs) {
    for (const char* e : DOH_ENDPOINTS) {
        std::string ip = dohQueryA(e, "example.com", timeoutMs);
        if (looksIPv4s(ip)) return e;
    }
    return "";
}

// ================== ВЕРДИКТ ПО ДОМЕНУ ==================
// Каскад проверок снизу вверх: DNS → IP (L3) → SNI (L7) → поведение.
enum class Block { Ok, DnsSpoof, IpBlock, SniBlock, GeoServer, Behavior, Unknown };

static const char* blockName(Block b) {
    switch (b) {
        case Block::Ok:       return "РАБОТАЕТ";
        case Block::DnsSpoof: return "ПОДМЕНА DNS";
        case Block::IpBlock:  return "БЛОК ПО IP";
        case Block::SniBlock: return "БЛОК ПО SNI";
        case Block::GeoServer:return "ГЕО/СЕРВЕР";
        case Block::Behavior: return "СБОЙ ПОВЕДЕНИЯ";
        default:              return "НЕ ОПРЕДЕЛЕНО";
    }
}
static const char* blockKey(Block b) {   // машиночитаемо — для вердикт-JSON (вход селектора транспорта)
    switch (b) {
        case Block::Ok:       return "ok";
        case Block::DnsSpoof: return "dns_spoof";
        case Block::IpBlock:  return "ip_block";
        case Block::SniBlock: return "sni_block";
        case Block::GeoServer:return "geo_server";
        case Block::Behavior: return "behavior";
        default:              return "unknown";
    }
}

// заведомо разрешённый хост: и «контроль живости сети», и «чистый» SNI на тот же IP
static const char* PROBE_CONTROL_DOMAIN = "ya.ru";
static const int PROBE_TRIES   = 2;   // повтор пробы: отсекаем разовые сетевые флапы от стабильного блока
static const size_t PROBE_MAX_IPS = 3; // сколько адресов домена проверять (ограничение времени)

// Проба с повтором: один успех = канал жив (ранний выход); иначе устойчивый неуспех после PROBE_TRIES.
static TlsProbe probeTlsStable(const std::string& ip, const std::string& sni, int timeoutMs, int tries) {
    TlsProbe last;
    for (int i = 0; i < tries; ++i) {
        last = probeTls(ip, sni, timeoutMs);
        if (last.outcome == TlsOutcome::Answered) return last;   // успех — канал жив
        if (last.outcome == TlsOutcome::Stall)    return last;   // зависание = полный таймаут, повтор не меняет → не ждём второй раз
    }
    return last;
}

struct Diagnosis {
    std::string domain, ipUsed, ipSystem, ipTrusted;
    bool dnsMismatch = false;
    TlsProbe real, clean;
    Block verdict = Block::Unknown;
    std::string explain;
    int ipsTotal = 1, ipsBlocked = 0;   // сколько адресов проверено / сколько прибито
};

static Diagnosis probeDomain(const std::string& domain, const std::string& dohEndpoint,
                             const std::string& trustedDns, int timeoutMs, bool controlOk) {
    Diagnosis d; d.domain = domain;

    d.ipSystem = resolveIPv4(domain);               // системный резолвер (первый адрес)

    // КАНДИДАТЫ-IP: все A-записи через DoH (мульти-IP!), иначе системный, иначе UDP-DNS
    std::vector<std::string> cand;
    if (!dohEndpoint.empty()) cand = dohQueryAll(dohEndpoint, domain, timeoutMs);
    if (cand.empty() && !d.ipSystem.empty()) cand.push_back(d.ipSystem);
    if (cand.empty() && !trustedDns.empty()) {
        long rtt = -1; std::string u = dnsQueryA(trustedDns, domain, timeoutMs, rtt);
        if (!u.empty()) cand.push_back(u);
    }
    if (cand.size() > PROBE_MAX_IPS) cand.resize(PROBE_MAX_IPS);

    d.ipTrusted = cand.empty() ? "" : cand[0];
    d.ipUsed    = d.ipTrusted;
    bool sysInSet = false; for (auto& c : cand) if (c == d.ipSystem) { sysInSet = true; break; }
    if (!d.ipSystem.empty() && !cand.empty() && !sysInSet) d.dnsMismatch = true;

    if (cand.empty()) { d.verdict = Block::DnsSpoof; d.explain = "не резолвится ни DoH, ни системным, ни UDP-DNS"; return d; }
    d.ipsTotal = (int)cand.size();

    if (!controlOk) {
        d.ipUsed = cand[0];
        d.real = probeTlsStable(cand[0], domain, timeoutMs, PROBE_TRIES);
        d.verdict = Block::Unknown; d.explain = "контроль недоступен — сеть/путь не работают, диагноз ненадёжен";
        return d;
    }

    // перебор IP: первый ответивший на реальный SNI → РАБОТАЕТ (канал жив); иначе копим типы блока
    int nIp = 0, nSni = 0, nGeo = 0, nBeh = 0, tested = 0;
    for (size_t i = 0; i < cand.size(); ++i) {
        TlsProbe real = probeTlsStable(cand[i], domain, timeoutMs, PROBE_TRIES);
        tested++;
        if (real.outcome == TlsOutcome::Answered) {
            d.ipUsed = cand[i]; d.real = real; d.clean = TlsProbe{};
            d.verdict = Block::Ok;
            d.explain = (cand.size() > 1)
                ? ("хост ответил на реальный SNI (живой IP " + cand[i] + " из " + std::to_string(cand.size()) + ")")
                : (d.dnsMismatch ? "работает; системный и доверенный DNS дали разные IP (CDN или подмена)"
                                 : "хост ответил на реальный SNI");
            return d;
        }
        TlsProbe clean = probeTlsStable(cand[i], PROBE_CONTROL_DOMAIN, timeoutMs, PROBE_TRIES);  // контроль на том же IP (с повтором — убирает флапы)
        bool cleanAns = (clean.outcome == TlsOutcome::Answered);
        Block b;
        if (real.outcome == TlsOutcome::NoConnect && clean.outcome == TlsOutcome::NoConnect)
            b = Block::IpBlock;                 // TCP мёртв при любом SNI → блок по IP (L3)
        else if (cleanAns && real.outcome != TlsOutcome::NoConnect)
            b = Block::SniBlock;                // чистый SNI отвечает, реальный режется → DPI по SNI
        else if (!cleanAns && (real.outcome == TlsOutcome::Stall  || real.outcome == TlsOutcome::Reset
                            || clean.outcome == TlsOutcome::Stall || clean.outcome == TlsOutcome::Reset))
            b = Block::GeoServer;               // TCP встаёт, но TLS мёртв при ЛЮБОМ SNI → гео/сервер режет, не DPI-SNI
        else
            b = Block::Behavior;                // смешанные флапы
        if      (b == Block::IpBlock)   nIp++;
        else if (b == Block::SniBlock)  nSni++;
        else if (b == Block::GeoServer) nGeo++;
        else                            nBeh++;
        if (d.ipUsed.empty() || d.real.outcome == TlsOutcome::NoConnect) { d.ipUsed = cand[i]; d.real = real; d.clean = clean; }
        // всё, кроме блока по IP, не зависит от конкретного адреса (живой IP нашли бы выше) — остальные не проверяем
        if (b != Block::IpBlock) break;
    }

    // ни один IP не ответил — доминирующий тип блока; при равенстве приоритет SNI (дешевле обходится) > IP > поведение
    d.ipsTotal = tested; d.ipsBlocked = tested;
    if (nSni >= nIp && nSni >= nGeo && nSni >= nBeh && nSni > 0) d.verdict = Block::SniBlock;
    else if (nIp >= nGeo && nIp >= nBeh && nIp > 0)              d.verdict = Block::IpBlock;
    else if (nGeo >= nBeh && nGeo > 0)                           d.verdict = Block::GeoServer;
    else                                                        d.verdict = Block::Behavior;

    std::string suffix;
    if (tested > 1)
        suffix = " [" + std::to_string(tested) + " IP: " + std::to_string(nSni) + " SNI / "
               + std::to_string(nIp) + " IP / " + std::to_string(nGeo) + " гео / " + std::to_string(nBeh) + " повед.]";
    if (d.verdict == Block::SniBlock)
        d.explain = "чистый SNI проходит, реальный режется → блок по SNI (DPI)" + suffix;
    else if (d.verdict == Block::IpBlock)
        d.explain = "TCP не встаёт ни с каким SNI, контроль работает → блок по IP (L3)" + suffix;
    else if (d.verdict == Block::GeoServer)
        d.explain = "TCP встаёт, но TLS мёртв при любом SNI → гео-блок сервиса или фильтр по IP, не DPI-SNI (нужен чистый выход, а не обход SNI)" + suffix;
    else
        d.explain = "смешанные/нестабильные ответы → поведение (имеет смысл повторить прогон)" + suffix;
    return d;
}

// ================== ВЕРДИКТ-JSON (вход для будущего селектора транспорта) ==================
static void writeVerdictJson(const std::string& txtLogFile, const std::vector<Diagnosis>& res) {
    if (txtLogFile.empty()) return;
    std::string jp = txtLogFile;
    size_t dot = jp.rfind('.'); if (dot != std::string::npos) jp = jp.substr(0, dot);
    jp += "_verdict.json";

    SYSTEMTIME st; GetLocalTime(&st);
    char ts[32];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::ostringstream j;
    j << "{\n  \"tool\": \"Lag\",\n  \"probe\": \"block-diagnose\",\n";
    j << "  \"version\": \"" << SCRIPT_VERSION << "\",\n";
    j << "  \"timestamp\": " << jStr(ts) << ",\n";
    j << "  \"results\": [";
    for (size_t i = 0; i < res.size(); i++) {
        const Diagnosis& d = res[i];
        j << (i ? ",\n" : "\n")
          << "    { \"domain\": "       << jStr(d.domain)
          << ", \"ip\": "              << jStr(d.ipUsed)
          << ", \"verdict\": "         << jStr(blockKey(d.verdict))
          << ", \"dns_mismatch\": "    << (d.dnsMismatch ? "true" : "false")
          << ", \"real_sni\": "        << jStr(d.real.note)
          << ", \"clean_sni\": "       << jStr(d.clean.note)
          << ", \"ips_total\": "       << d.ipsTotal
          << ", \"ips_blocked\": "     << d.ipsBlocked
          << " }";
    }
    j << (res.empty() ? "" : "\n  ") << "]\n}\n";
    std::ofstream f(jp, std::ios::binary);
    if (f) f << j.str();
}

// ================== UDP / STUN проба ==================
// Проверяет, проходит ли UDP на этой сети и жив ли STUN — фундамент для WebRTC (olcbox/Телемост),
// Hysteria/QUIC и диагностики голосовых (Discord). Шлём настоящий STUN Binding Request по UDP
// и смотрим, вернулся ли ответ с нашим внешним адресом.
struct StunResult {
    std::string server; int port = 0;
    bool ok = false;            // пришёл валидный STUN-ответ (UDP прошёл туда-обратно)
    std::string mapped;         // внешний адрес из XOR-MAPPED-ADDRESS
    std::string note;
};

// Один STUN-запрос на УЖЕ открытом сокете (для NAT-теста важно слать с одного порта).
struct StunRaw { bool answered = false; std::string mapped; std::string note; };
static StunRaw stunMappedOn(SOCKET s, const std::string& ip, int port, int timeoutMs) {
    StunRaw r;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
    if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) { r.note = "плохой IP"; return r; }

    unsigned char req[20];
    req[0] = 0x00; req[1] = 0x01; req[2] = 0x00; req[3] = 0x00;
    req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42;
    for (int i = 8; i < 20; i++) req[i] = (unsigned char)(rand() & 0xFF);
    if (sendto(s, (const char*)req, 20, 0, (sockaddr*)&a, sizeof(a)) != 20) { r.note = "UDP send не прошёл"; return r; }

    unsigned char buf[512]; sockaddr_in from{}; socklen_t fl = sizeof(from);
    int n = recvfrom(s, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
    if (n < 20) { r.note = (n < 0 ? "нет ответа (UDP режется?)" : "короткий ответ"); return r; }
    if (!(buf[0] == 0x01 && buf[1] == 0x01)) { r.note = "ответ не STUN"; return r; }

    int alen = (buf[2] << 8) | buf[3]; int end = 20 + alen; if (end > n) end = n; int pos = 20;
    while (pos + 4 <= end) {
        int atype = (buf[pos] << 8) | buf[pos + 1];
        int aln   = (buf[pos + 2] << 8) | buf[pos + 3];
        int ap = pos + 4;
        if ((atype == 0x0020 || atype == 0x0001) && ap + 8 <= n && buf[ap + 1] == 0x01) {
            int xport = (buf[ap + 2] << 8) | buf[ap + 3];
            unsigned char ipb[4]; for (int i = 0; i < 4; i++) ipb[i] = buf[ap + 4 + i];
            if (atype == 0x0020) { xport ^= 0x2112; ipb[0] ^= 0x21; ipb[1] ^= 0x12; ipb[2] ^= 0xA4; ipb[3] ^= 0x42; }
            char tmp[32]; snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d:%d", ipb[0], ipb[1], ipb[2], ipb[3], xport);
            r.mapped = tmp;
        }
        pos += 4 + aln + ((4 - (aln & 3)) & 3);
    }
    r.answered = true;
    r.note = r.mapped.empty() ? "STUN ответил" : ("STUN ok, внешний " + r.mapped);
    return r;
}

static StunResult probeStun(const std::string& host, int port, int timeoutMs) {
    StunResult r; r.server = host; r.port = port;
    std::string ip = resolveIPv4(host);
    if (ip.empty()) { r.note = "не резолвится"; return r; }
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { r.note = "нет UDP-сокета"; return r; }
    setSockTimeoutMs(s, timeoutMs);
    StunRaw raw = stunMappedOn(s, ip, port, timeoutMs);
    closesocket(s);
    r.ok = raw.answered; r.mapped = raw.mapped; r.note = raw.note;
    return r;
}

// NAT-тип ПРАВИЛЬНО: два разных сервера с ОДНОГО сокета/порта; сравниваем внешний адрес.
static std::string natCheck(const std::vector<std::pair<std::string,int>>& responders, int timeoutMs) {
    if (responders.size() < 2) return "не определён (нужно ≥2 ответивших сервера)";
    std::string ipA = resolveIPv4(responders[0].first), ipB = resolveIPv4(responders[1].first);
    if (ipA.empty() || ipB.empty()) return "не определён (резолв)";
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return "не определён (нет сокета)";
    setSockTimeoutMs(s, timeoutMs);
    StunRaw a = stunMappedOn(s, ipA, responders[0].second, timeoutMs);
    StunRaw b = stunMappedOn(s, ipB, responders[1].second, timeoutMs);
    closesocket(s);
    if (!a.answered || !b.answered || a.mapped.empty() || b.mapped.empty())
        return "не определён (мало ответов с одного порта)";
    if (a.mapped == b.mapped)
        return "конусный — внешний адрес с одного порта стабилен (" + a.mapped + "), P2P/WebRTC/Телемост обычно работают";
    return "симметричный — внешний адрес зависит от назначения (" + a.mapped + " vs " + b.mapped + "), прямой P2P/Телемост могут не встать (нужен TURN/relay)";
}

static void writeUdpJson(const std::string& txtLogFile, const std::vector<StunResult>& res, bool udpOk, const std::string& ext, const std::string& nat) {
    if (txtLogFile.empty()) return;
    std::string jp = txtLogFile;
    size_t dot = jp.rfind('.'); if (dot != std::string::npos) jp = jp.substr(0, dot);
    jp += "_udp.json";
    SYSTEMTIME st; GetLocalTime(&st);
    char ts[32];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::ostringstream j;
    j << "{\n  \"tool\": \"Lag\",\n  \"probe\": \"udp-stun\",\n";
    j << "  \"version\": \"" << SCRIPT_VERSION << "\",\n";
    j << "  \"timestamp\": " << jStr(ts) << ",\n";
    j << "  \"udp_ok\": " << (udpOk ? "true" : "false") << ",\n";
    j << "  \"external\": " << jStr(ext) << ",\n";
    j << "  \"nat_type\": " << jStr(nat) << ",\n";
    j << "  \"servers\": [";
    for (size_t i = 0; i < res.size(); i++) {
        const StunResult& r = res[i];
        j << (i ? ",\n" : "\n")
          << "    { \"server\": " << jStr(r.server)
          << ", \"port\": " << r.port
          << ", \"ok\": " << (r.ok ? "true" : "false")
          << ", \"mapped\": " << jStr(r.mapped)
          << ", \"note\": " << jStr(r.note)
          << " }";
    }
    j << (res.empty() ? "" : "\n  ") << "]\n}\n";
    std::ofstream f(jp, std::ios::binary);
    if (f) f << j.str();
}

// Запускается в конце ЗОНДа: карта UDP-портов (какие пропускает оператор) + оценка NAT.
static void runStunProbe(const std::string& logFile) {
    int timeoutMs = std::max(g_config.HttpTimeout, 1) * 1000;
    struct Srv { std::string host; int port; };
    std::vector<Srv> servers = {
        { "stun.l.google.com", 19302 },
        { "stun.cloudflare.com", 3478 },
        { "stun.nextcloud.com", 443 },
        { "openrelay.metered.ca", 80 },
        { "stun.sipgate.net", 3478 },
    };
    // свои цели (свой сервер, позже — Телемост): stun_targets.txt, строки host:port
    for (auto& it : loadItemList("stun_targets.txt")) {
        std::string v = it.Value; if (v.empty()) continue;
        size_t c = v.rfind(':'); int port = 3478; std::string host = v;
        if (c != std::string::npos) { host = v.substr(0, c); int p = atoi(v.substr(c + 1).c_str()); if (p > 0) port = p; }
        servers.push_back({ host, port });
    }

    writeLog("\n--- UDP / STUN (карта UDP-портов и WebRTC-путь) ---", "Green", logFile);
    std::vector<std::string> headers = { "STUN-сервер", "Порт", "Результат" };
    std::vector<size_t> minW = { 24, 5, 30 };
    auto w = tableWidths(headers, minW);
    tableHead(headers, w, logFile);

    std::vector<StunResult> res;
    std::vector<std::string> mapped;                 // внешние адреса ответивших (для вывода)
    std::vector<std::pair<std::string,int>> responders;  // ответившие серверы (для NAT-теста)
    std::vector<std::pair<int,bool>> portOk;         // порт → отвечал ли хоть один сервер на нём
    for (auto& srv : servers) {
        StunResult r = probeStun(srv.host, srv.port, timeoutMs);
        res.push_back(r);
        bool found = false;
        for (auto& pr : portOk) if (pr.first == srv.port) { if (r.ok) pr.second = true; found = true; break; }
        if (!found) portOk.push_back({ srv.port, r.ok });
        if (r.ok && !r.mapped.empty()) { mapped.push_back(r.mapped); responders.push_back({ srv.host, srv.port }); }
        tableRow({ srv.host, std::to_string(srv.port), r.note }, w, r.ok ? "Green" : "Red", logFile);
    }
    tableSep(w, logFile);

    // карта портов: какие UDP-порты пропускаются
    std::string pm = "UDP-порты: ";
    for (auto& pr : portOk) pm += std::to_string(pr.first) + (pr.second ? " да   " : " нет  ");
    writeLog(pm, "Cyan", logFile);

    // NAT-тип: корректная проверка с одного сокета к двум серверам
    std::string nat = natCheck(responders, timeoutMs);

    bool udpOk = !mapped.empty();
    if (udpOk) writeLog("UDP проходит. Внешний: " + mapped[0] + ". NAT: " + nat, "Cyan", logFile);
    else       writeLog("UDP/STUN не отвечает нигде → UDP на этой сети режется, нужен TCP-транспорт.", "Yellow", logFile);
    writeLog("(карта грубая: мёртвый сервер выглядит как закрытый порт; для точной карты впиши свой сервер в stun_targets.txt)", "Gray", logFile);

    writeUdpJson(logFile, res, udpOk, mapped.empty() ? "" : mapped[0], nat);
    writeLog("UDP-результат сохранён рядом: " +
             toU8(logFile).substr(0, toU8(logFile).rfind('.')) + "_udp.json", "Gray", logFile);
}

// ================== ТЕСТЕР ОБХОДА SNI ==================
// Для домена с блоком по SNI пробуем СТРИМ-уровневые приёмы десинхронизации DPI и смотрим,
// какой пропускает ServerHello. Пакетные приёмы (fake-пакет, низкий TTL, seqovl) требуют
// драйвера WinDivert и здесь НЕ делаются — только то, что возможно на обычном TCP-сокете.
enum class Ev { SplitSNI, RecordSplit, SplitFirst, MultiSplit };

static int findSniOffset(const std::vector<uint8_t>& rec, const std::string& sni) {
    if (sni.empty() || rec.size() < sni.size()) return -1;
    for (size_t i = 0; i + sni.size() <= rec.size(); i++) {
        bool eq = true;
        for (size_t k = 0; k < sni.size(); k++) if (rec[i + k] != (uint8_t)sni[k]) { eq = false; break; }
        if (eq) return (int)i;
    }
    return -1;
}

// отправить байты, разрезая поток в точках cuts (каждый кусок уходит отдельным TCP-сегментом)
static bool sendCut(SOCKET s, const std::vector<uint8_t>& d, const std::vector<int>& cuts) {
    std::vector<int> pts = cuts; pts.push_back((int)d.size());
    int prev = 0;
    for (int p : pts) {
        if (p > (int)d.size()) p = (int)d.size();
        int off = prev;
        while (off < p) { int w = send(s, (const char*)d.data() + off, p - off, 0); if (w <= 0) return false; off += w; }
        prev = p;
        Sleep(8);   // микропауза, чтобы сегменты не слиплись в один пакет
    }
    return true;
}

// пересобрать ClientHello как ДВЕ TLS-записи (SNI уводим во вторую); boundary = конец первой записи
static std::vector<uint8_t> buildTwoRecords(const std::vector<uint8_t>& rec, int sniOffInRec, int& boundary) {
    std::vector<uint8_t> hs(rec.begin() + 5, rec.end());   // handshake без record-заголовка
    int n = (int)hs.size();
    int split = (sniOffInRec >= 8) ? (sniOffInRec - 5 - 3) : (n / 2);   // чуть раньше hostname
    if (split < 1) split = 1;
    if (split >= n) split = n / 2;
    std::vector<uint8_t> out;
    auto emit = [&](int from, int to) {
        int len = to - from;
        out.push_back(0x16); out.push_back(0x03); out.push_back(0x01);
        out.push_back((uint8_t)(len >> 8)); out.push_back((uint8_t)(len & 0xFF));
        out.insert(out.end(), hs.begin() + from, hs.begin() + to);
    };
    emit(0, split);
    boundary = (int)out.size();
    emit(split, n);
    return out;
}

static bool probeEvasion(const std::string& ip, const std::string& sni, Ev e, int timeoutMs) {
    std::vector<uint8_t> rec = buildClientHello(sni);
    int sniOff = findSniOffset(rec, sni);
    SOCKET s = connectTcp(ip, 443, timeoutMs);
    if (s == INVALID_SOCKET) return false;
    int one = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));

    bool sent = false;
    if (e == Ev::SplitFirst) {
        sent = sendCut(s, rec, { 1 });
    } else if (e == Ev::MultiSplit) {
        std::vector<int> cuts; for (int i = 16; i < (int)rec.size(); i += 16) cuts.push_back(i);
        sent = sendCut(s, rec, cuts);
    } else if (e == Ev::SplitSNI) {
        int cut = (sniOff < 0) ? (int)rec.size() / 2 : sniOff + (int)sni.size() / 2;
        sent = sendCut(s, rec, { cut });
    } else { // RecordSplit
        int boundary = 0;
        std::vector<uint8_t> two = buildTwoRecords(rec, sniOff, boundary);
        sent = sendCut(s, two, { boundary });
    }
    if (!sent) { closesocket(s); return false; }

    unsigned char buf[512];
    int n = recv(s, (char*)buf, sizeof(buf), 0);
    closesocket(s);
    return (n > 0 && buf[0] == 0x16);   // ServerHello = приём пробил блок
}

static void runEvasionTest(const std::string& logFile, const std::vector<std::pair<std::string,std::string>>& blocked) {
    if (blocked.empty()) return;
    int to = g_config.HttpTimeout; if (to > 3) to = 3; if (to < 1) to = 1;
    int timeoutMs = to * 1000;
    const size_t CAP = 6;

    writeLog("\n--- ОБХОД SNI (чем пробивается блок по SNI) ---", "Green", logFile);
    writeLog("(стрим-уровень: нарезка TCP-сегментов и фрагментация TLS-записи; пакетные приёмы fake/TTL/seqovl требуют WinDivert — пока не тут)", "Gray", logFile);
    if (blocked.size() > CAP)
        writeLog("Проверяю первые " + std::to_string(CAP) + " из " + std::to_string(blocked.size()) + " SNI-заблокированных доменов.", "Gray", logFile);

    std::vector<std::string> headers = { "Домен", "Чем пробивается" };
    std::vector<size_t> minW = { 18, 26 };
    for (auto& b : blocked) minW[0] = std::max(minW[0], dispLen(b.first));
    auto w = tableWidths(headers, minW);
    tableHead(headers, w, logFile);

    struct St { Ev e; const char* name; };
    static const St order[] = {
        { Ev::SplitSNI,    "сплит по SNI" },
        { Ev::RecordSplit, "фрагментация TLS-записи" },
        { Ev::SplitFirst,  "сплит первого байта" },
        { Ev::MultiSplit,  "мелкая нарезка" },
    };

    std::vector<std::pair<std::string,std::string>> found;
    size_t done = 0;
    for (auto& b : blocked) {
        if (done++ >= CAP) break;
        std::string win = "-";
        for (auto& st : order)
            if (probeEvasion(b.second, b.first, st.e, timeoutMs)) { win = st.name; break; }
        found.push_back({ b.first, win });
        tableRow({ b.first, win }, w, win == "-" ? "Red" : "Green", logFile);
    }
    tableSep(w, logFile);

    int ok = 0; for (auto& f : found) if (f.second != "-") ok++;
    writeLog("Пробито " + std::to_string(ok) + " из " + std::to_string((int)found.size()) +
             ". Если ноль — стрим-приёмы этот ТСПУ не берёт, нужен WinDivert (fake/TTL/seqovl) или relay.",
             ok > 0 ? "Cyan" : "Yellow", logFile);

    if (!logFile.empty()) {
        std::string jp = logFile; size_t dot = jp.rfind('.'); if (dot != std::string::npos) jp = jp.substr(0, dot);
        jp += "_evasion.json";
        std::ostringstream j;
        j << "{\n  \"tool\": \"Lag\",\n  \"probe\": \"sni-evasion\",\n  \"results\": [";
        for (size_t i = 0; i < found.size(); i++)
            j << (i ? ",\n" : "\n") << "    { \"domain\": " << jStr(found[i].first)
              << ", \"bypass\": " << jStr(found[i].second == "-" ? "" : found[i].second) << " }";
        j << (found.empty() ? "" : "\n  ") << "]\n}\n";
        std::ofstream f(jp, std::ios::binary); if (f) f << j.str();
    }
}

// ================== БЫСТРАЯ ПРОВЕРКА ДОСТУПНОСТИ (SITES, вариант 2) ==================
// Резолв через DoH (обходит подмену UDP-DNS) + TLS-проба с настоящим SNI — отвечает
// на вопрос «открывается ли сайт», как браузер. Это легче ЗОНДа: одна IP, без клон-SNI.
// Точный тип блока (SNI / IP / DNS) по-прежнему даёт ЗОНД.
static bool runSitesCheck(const std::string& logFile, const std::vector<Item>& targets) {
    int timeoutMs = std::max(g_config.HttpTimeout, 1) * 1000;
    writeLog("\n--- ДОСТУПНОСТЬ САЙТОВ (DoH + TLS с SNI) ---", "Green", logFile);
    if (targets.empty()) { writeLog(" Нет сайтов. Заполни sites.txt.", "Red", logFile); return false; }

    writeLog("Внешний IP (текущий путь): " + getExternalGeo(), "Cyan", logFile);

    std::string trustedDns = "8.8.8.8";
    { auto dt = loadItemList("dns_targets.txt"); if (!dt.empty()) trustedDns = dt[0].Value; }
    std::string doh = pickDoh(timeoutMs);
    if (!doh.empty()) {
        std::string host = doh.substr(8, doh.find('/', 8) - 8);
        writeLog("Резолв через DoH " + host + " (обходит подмену UDP-DNS; запас UDP: " + trustedDns + ")", "Green", logFile);
    } else {
        writeLog("DoH недоступен, резолв по UDP " + trustedDns + " — его могут подменять!", "Yellow", logFile);
    }
    writeLog("Проба открывает настоящее TLS к сайту (обычный трафик). Точный тип блока — в разделе ЗОНД.", "Gray", logFile);
    writeLog("", "White", logFile);

    std::vector<std::string> headers = { "Сайт", "IP (DoH)", "Доступ" };
    std::vector<size_t> minW = { 4, 15, 24 };
    for (auto& t : targets) minW[0] = std::max(minW[0], dispLen(t.Value));
    auto w = tableWidths(headers, minW);
    tableHead(headers, w, logFile);

    int okN = 0, badN = 0, dnsN = 0;
    for (auto& t : targets) {
        if (t.Value.empty()) continue;
        if (t.Value.find(':') != std::string::npos) { tableRow({ t.Value, "IPv6", "пропуск" }, w, "Gray", logFile); continue; }

        std::string ip;
        if (!doh.empty()) { auto all = dohQueryAll(doh, t.Value, timeoutMs); if (!all.empty()) ip = all[0]; }
        if (ip.empty() && !trustedDns.empty()) { long rtt = -1; ip = dnsQueryA(trustedDns, t.Value, timeoutMs, rtt); }
        if (ip.empty()) ip = resolveIPv4(t.Value);     // последний шанс — системный резолвер

        if (ip.empty()) { tableRow({ t.Value, "-", "НЕ РЕЗОЛВИТСЯ (подмена DNS)" }, w, "Red", logFile); dnsN++; continue; }

        TlsProbe pr = probeTlsStable(ip, t.Value, timeoutMs, PROBE_TRIES);
        std::string status, col;
        if (pr.outcome == TlsOutcome::Answered && pr.tlsReply) { status = "ДОСТУПЕН (" + std::to_string(pr.replyMs) + "мс)"; col = "Green"; okN++; }
        else if (pr.outcome == TlsOutcome::Answered)           { status = "ОТВЕТ НЕ TLS (заглушка?)"; col = "Yellow"; badN++; }
        else if (pr.outcome == TlsOutcome::Reset)              { status = "РВЁТСЯ (RST/FIN)"; col = "Red"; badN++; }
        else if (pr.outcome == TlsOutcome::Stall)              { status = "ТИШИНА (дроп)"; col = "Red"; badN++; }
        else                                                   { status = "TCP НЕ ВСТАЁТ"; col = "Red"; badN++; }
        tableRow({ t.Value, ip, status }, w, col, logFile);
    }
    tableSep(w, logFile);
    writeLog("", "White", logFile);
    writeLog("ДОСТУПЕН — сайт открывается (TLS с его SNI прошёл). РВЁТСЯ/ТИШИНА — режет DPI. НЕ РЕЗОЛВИТСЯ — подмена DNS.", "Gray", logFile);
    writeLog("Итого: доступно " + std::to_string(okN) + ", режется " + std::to_string(badN) +
             ", не резолвится " + std::to_string(dnsN) + ". Точный тип блока — в ЗОНДе.", "Cyan", logFile);
    return true;
}

// ================== ТОЧКА ВХОДА (сигнатура как у invokeServiceScan) ==================
// Повесь вызов на любой пункт меню: runBlockProbe(lf, loadItemList("sites.txt"))
static bool runBlockProbe(const std::string& logFile, const std::vector<Item>& targets) {
    int timeoutMs = std::max(g_config.HttpTimeout, 1) * 1000;
    writeLog("\n--- ДИАГНОСТИКА БЛОКИРОВКИ (SNI-проба) ---", "Green", logFile);
    if (targets.empty()) { writeLog(" Нет целей. Заполни sites.txt.", "Red", logFile); return false; }

    // доверенный DNS для сверки: первый из dns_targets.txt, иначе 8.8.8.8
    std::string trustedDns = "8.8.8.8";
    { auto dt = loadItemList("dns_targets.txt"); if (!dt.empty()) trustedDns = dt[0].Value; }

    // доверенный резолвер через DoH — его UDP-перехватом не подменить
    std::string doh = pickDoh(timeoutMs);

    // контроль «сеть жива»: заведомо разрешённый хост должен ответить
    std::string cip = resolveIPv4(PROBE_CONTROL_DOMAIN);
    TlsProbe ctl = cip.empty() ? TlsProbe{} : probeTls(cip, PROBE_CONTROL_DOMAIN, timeoutMs);
    bool controlOk = (ctl.outcome == TlsOutcome::Answered);
    writeLog(std::string("Контроль (") + PROBE_CONTROL_DOMAIN + "): " +
             (controlOk ? "ответил — сеть и TLS работают"
                        : "НЕ ответил — сеть или путь не работают, диагнозы ненадёжны"),
             controlOk ? "Cyan" : "Red", logFile);
    if (!doh.empty()) {
        std::string host = doh.substr(8, doh.find('/', 8) - 8);   // хост из https://<host>/...
        writeLog("Доверенный DNS: DoH " + host + " (запасной UDP: " + trustedDns + ")", "Green", logFile);
    } else {
        writeLog("Доверенный DNS: DoH недоступен, откат на UDP " + trustedDns +
                 " — осторожно, его могут подменять!", "Yellow", logFile);
    }
    writeLog("(проба открывает настоящие TLS-соединения к целям — это обычный трафик)", "Gray", logFile);
    writeLog("", "White", logFile);

    std::vector<std::string> headers = { "Домен", "IP", "Реальный SNI", "Чистый SNI", "Вердикт" };
    std::vector<size_t> minW = { 4, 15, 18, 18, 14 };
    for (auto& t : targets) minW[0] = std::max(minW[0], dispLen(t.Value));
    auto w = tableWidths(headers, minW);
    tableHead(headers, w, logFile);

    std::vector<Diagnosis> res;
    std::vector<std::pair<std::string,std::string>> sniBlocked;   // домен+IP для теста обхода
    for (auto& t : targets) {
        if (t.Value.empty()) continue;
        if (t.Value.find(':') != std::string::npos) {   // IPv6 пока пропускаем (connectTcp по IPv4)
            tableRow({ t.Value, "IPv6", "-", "-", "пропуск" }, w, "Gray", logFile);
            continue;
        }
        Diagnosis d = probeDomain(t.Value, doh, trustedDns, timeoutMs, controlOk);
        res.push_back(d);
        if (d.verdict == Block::SniBlock && !d.ipUsed.empty()) sniBlocked.push_back({ d.domain, d.ipUsed });
        std::string col = (d.verdict == Block::Ok) ? "Green"
                        : (d.verdict == Block::SniBlock || d.verdict == Block::DnsSpoof) ? "Yellow"
                        : (d.verdict == Block::GeoServer) ? "Magenta"
                        : (d.verdict == Block::Unknown) ? "Gray" : "Red";
        tableRow({ d.domain, d.ipUsed.empty() ? "-" : d.ipUsed,
                   d.real.note, d.clean.note.empty() ? "-" : d.clean.note, blockName(d.verdict) },
                 w, col, logFile);
        writeVerdictJson(logFile, res);   // пишем по ходу — даже прерванный прогон оставит JSON
    }
    tableSep(w, logFile);
    writeLog("", "White", logFile);

    // расшифровка логики по каждому домену
    for (auto& d : res)
        writeLog("  " + d.domain + " → " + blockName(d.verdict) + ": " + d.explain,
                 d.verdict == Block::Ok ? "Gray" : "White", logFile);

    writeVerdictJson(logFile, res);
    writeLog("\nВердикт по доменам сохранён рядом: " +
             toU8(logFile).substr(0, toU8(logFile).rfind('.')) + "_verdict.json", "Gray", logFile);

    runEvasionTest(logFile, sniBlocked);   // тест обхода SNI
    runStunProbe(logFile);   // UDP/STUN-секция
    return true;
}
