# GLM-ревью безопасности — 2026-11-05

Срез: ветка `socks-carrier-160-20261104`, HEAD `b8982e3` (`git diff main...HEAD`), работа в изолированном worktree на `b2f793c`; исходники obfs4/webtunnel/core, не затронутые веткой, сверены с main (diff пуст — содержание идентично). Методика: rust-intel `security.md` (§B12, §B24, §C2) + `unsafe-and-ffi.md` (§B5, §B7, §B18, §B18a, §B25, §B25a) + SKILL.md Enforcement tiers / Blocking protocol (read-only: недостающие threat models зафиксированы как находки-ограничения, не блокируют). Production-код не редактировался, cargo не запускался. Read-only аудит ветки выполнен через `git show`/`git diff` без переключения ветки.

Resolved-версии ключевых deps (Cargo.lock ветки): rustls 0.23.46, rustls-webpki 0.103.16, rustls-pki-types 1.15.1, webpki-roots 0.26.11 + 1.0.11, tokio 1.54.1, tokio-util 0.7.19, resocks5-net 0.4.1 (registry, checksum `ccc65469…`, deps: base64/socket2/tokio), curve25519-dalek 4.1.3, x25519-dalek 2.0.1, curve25519-elligator2 0.1.0-alpha.2, rand 0.8.8 / 0.9.5 / 0.10.2 (rand_core 0.6.4 / 0.9.5 / 0.10.1), getrandom 0.2.17 / 0.3.4 / 0.4.3, hickory-resolver/proto 0.26.2, crypto_secretbox 0.1.1 (chacha20 0.10.2, poly1305 0.8.0), siphasher 1.0.3, subtle 2.6.1, zeroize 1.9.0, hkdf 0.12.4, hmac 0.12.1, sha2 0.10.9, httparse 1.10.1, url 2.5.8, percent-encoding 2.3.2, tor-bytes/tor-llcrypto 0.47.0, anyhow 1.0.104, socket2 0.6.5, base64 0.22.1.

Шкала: P0 — критическая неисправность; P1 — высокая срочность; P2 — исправить в обычном цикле; P3 — ограниченное влияние / устойчивость. Статус находок: **открыта**.

## Сводка

| ID | P | Область | file:line | Находка |
|---|---|---|---|---|
| GLMS-01 | P2 | Новый прокси-носитель / webtunnel `addr=` | crates/lyrebird/src/client/proxy.rs:103,133; crates/webtunnel/src/lib.rs:256,479 | Нет reject CR/LF/NUL в `host` на пути HTTP CONNECT к upstream-прокси; `addr=`-host проходит вебтуннельную валидацию с CR/LF |
| GLMS-02 | P2 | obfs4 §B12 логи | crates/obfs4/src/framing/codecs.rs:395-399,419-423,473; crates/obfs4/src/handshake/handshake_client.rs:120; crates/obfs4/src/handshake/handshake_server.rs:247,283-287 | Секретно-производный материал (nonce-префикс, mask длины, полные MAC, весь шифротекст) в debug!/trace! |
| GLMS-03 | P2 | webtunnel DoH-пул | crates/webtunnel/src/dns/endpoints.rs:132,150,174,186 | 4 из 10 SNI `.intra` не совпадают с сертификатами провайдеров —Endpoints всегда мертвы (fail closed, но 40% пула недоступно) |
| GLMS-04 | P3 | obfs4 §B12 API | crates/obfs4/src/common/drbg.rs:152-156 | Секретный `Seed` несёт полный hex через `Display` при редактированном `Debug` — асимметрия, каждый новый `{}`-сайт утечки |
| GLMS-05 | P3 | core §C2 | crates/core/src/helpers.rs:203-204 | Ошибка парсинга `TOR_PT_PROXY` включает полный URI с `user:password` в текст |
| GLMS-06 | P3 | Supply chain §A1 | Cargo.lock (`resocks5-net 0.4.1`) | Новый внешний крейт парсит ответы недоверенного ответа прокси; реализация (`http_connect_handshake` bounds, REP-коды) локально не проверяема |
| GLMS-07 | P3 | obfs4 §B12 | crates/obfs4/src/common/x25519_elligator2.rs:150-155 | `unwrap()` на `to_representative` в `From`-имплe — паника возможна только для ключей вне конструкторов `Keys` |

Итого: **P0: 0; P1: 0; P2: 3; P3: 4**.

## Находки

### GLMS-01 — P2 — CRLF-инъекция в HTTP CONNECT к upstream-прокси (defense-in-depth)

**Где:** `crates/lyrebird/src/client/proxy.rs:102-104`:

```rust
pub(crate) async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
    if self.protocol == ProxyProtocol::Https || host.is_empty() || host.len() > 255 || port == 0
    {
        return Err(failure());
    }
```

… далее `proxy.rs:133`: `let target = HostPort::format(host, port);` → `http_connect_handshake(&mut stream, &target, &config)` — `target` попадает в строку запроса `CONNECT … HTTP/1.1` к upstream-прокси.

Кормящий источник — `crates/webtunnel/src/lib.rs:256` (ветка `addr=`):

```rust
if host.is_empty() || host.contains([':', '[', ']']) {
    return Err(Error::InvalidUrl(format!("invalid addr= host: {host}")));
}
```

— CR/LF/NUL/пробелы не отвергаются; `prepared.host` из `addr=` уходит через новый `carrier_destination()` (`lib.rs:479`) в `proxy.connect(&host, port)`.

**Механизм:** значение `addr=` приходит из bridge-line (PT-аргументы, `configure_builder` → `WebTunnelConfig::from_args`). Дистрибьютор мостов (или скомпрометированный torrc/мост-лист) может подать `addr=host%0AX-Header: x:1080`-подобное значение; на HTTP-носители через upstream-прокси декодированный CR/LF попадает в request-line CONNECT и вклеивает attacker-выбранные строки запроса/заголовки в уже-аутентифицированную сессию с прокси (CWE-117/147, та же семья, что RUSTSEC-2026-0271). Для SOCKS5-носителя инъекции нет (бинарный length-prefixed формат, длина ≤ 255 проверена). obfs4-путь безопасен: host = `remote_addr.ip().to_string()` — IP-литерал (`lib.rs`, impl ManagedClient for obfs4::Client). URL-derived host вебтуннеля безопасен: WHATWG-парсер отвергает control-байты в host. Остаётся ровно один вектор: `addr=`-host на HTTP-прокси.

**Сценарий:** оператор подписывается на мост-лист третьей стороны; malicious `addr=` → при каждом клиентском диале через HTTP-прокси прокси получает дописанные строки (лог-поллution до request smuggling на прокси-хопе в зависимости от реализации прокси).

**Фикс:** (1) в `proxy.connect` — per-byte reject для HTTP-ветки: `host.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b':' || b == b'[' || b == b']')` → `Err(failure())` (тот же стиль, что в `Proxy::parse` для authority); (2) в `PreparedConfig::new` — дополнить валидацию `addr=`-host reject CR/LF/NUL; тесты с `"host\r\nX: y"` (не доходит до сети — parse/connect).

### GLMS-02 — P2 — §B12: секретно-производный материал в debug/trace логах

**Где и что:**
- `crates/obfs4/src/framing/codecs.rs:473`: `trace!("fresh nonce: {}", hex::encode(nonce));` — nonce = 16-байтный **секретный префикс** (часть KEY_MATERIAL сессии) + счётчик.
- `crates/obfs4/src/framing/codecs.rs:395-399`: `debug!("encoding➡️ {length}B, {length:04x}^{length_mask:04x} {:04x}", length ^ length_mask)` — печатаются и открытая длина, и маска → по логам+wire восстанавливается выход DRBG маскирования; `codecs.rs:419-423`: `trace!("prng_ciphertext: …", hex::encode(&dst[tag_start…]))` — весь шифротекст с тегом.
- `crates/obfs4/src/handshake/handshake_client.rs:120`: `debug!("{} != {}", hex::encode(auth), hex::encode(authcode));` — вычисленный HMAC-автотег (секретно-производный) на failure-пути.
- `crates/obfs4/src/handshake/handshake_server.rs:247,283-287`: `trace!("{} mark?:{}"…)` и `trace!("server {}-{}"…, mac_calculated, mac_received)` — серверные MAC, вычисленные ключом identity, по одному на каждую эпоху slack-окна.

**Механизм/сценарий:** требует чтения локальных логов (threat model obfs4 — сетевой наблюдатель, логи обычно на стороне оператора), но §B12 прямо запрещает вывод секретов через `{:?}`/hex в логи: (а) маска+wire-длина деанонимизируют трафик-анализ сессии (подрыв назначения length-obfuscation); (б) nonce-префикс в логах — утечка 16 байт ключевого материала; (в) вычисленные MAC в логах — материал для офлайн-подбора/корреляции ключей identity при повторном использовании логов. Часть кода — прямые порты Go-референса, который этого не логирует.

**Фикс:** удалить или редактировать: nonce — печатать только счётчик; `prng_ciphertext`/`encoding➡️` — убрать (или печатать только длину без маски); MAC-дампы в client/server handshake — заменить на `debug!("mac mismatch")` без hex. Проверить, что default-фильтры (`default_filter_directives`) не включают trace в проде.

### GLMS-03 — P2 — webtunnel DoH-пул: несуществующие SNI у 4 из 10 провайдеров

**Где:** `crates/webtunnel/src/dns/endpoints.rs:132` `sni: "cloudflare-dns.intra"`, `:150` `"dns.adguard-dns.intra"`, `:174` `"freedns.controld.intra"`, `:186` `"doh.opendns.intra"`.

**Механизм:** hickory `NameServerConfig::https(ip, server_name, path)` валидирует сертификат против SNI по webpki-корням. Реальные имена: `cloudflare-dns.com` (Cloudflare также `one.one.one.one`), `dns.adguard-dns.com`, `freedns.controld.com`, `doh.opendns.com`. `.intra` — не делегированный публичный TLD; CA из webpki-корней сертификат на него не выпускает, серверы его не отдают → TLS-handshake этих 4 endpoints падает всегда. Валидация **не ослаблена** (fail closed), но 40% пула мертвы: DoH-запросы ротируются по мёртвым записям (latency, ретраи), и в `Strict`-режиме censorship-устойчивость деградирует ровно там, где она нужна. Тест `all_default_endpoints_well_formed` проверяет формат, не достижимость SNI.

**Фикс:** исправить 4 SNI на реальные `.com`-имена; добавить тест/CI-проверку соответствия SNI известным провайдерским именам (offline-список) — форматный тест это не ловит по построению.

### GLMS-04 — P3 — `drbg::Seed`: секрет через `Display` при редактированном `Debug`

**Где:** `crates/obfs4/src/common/drbg.rs:152-156`:

```rust
impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..]))
    }
}
```

**Механизм:** Debug-импл редактирован (`"drbg::Seed(..)"`, drbg.rs:23-29) с комментарием «secret key material», но Display печатает полный seed (ключ SipHash длино-маскирования). Текущие пользователи — операторская поверхность по дизайну: bridge-line `args.add(SEED_ARG, &seed)` (server.rs:487) и statefile (server.rs:705). Опасность — API-ловушка: любой будущий `format!("{seed}")` в error/log-пути молча выводит секрет, а grep по `{:?}` его не найдёт (redacted-Debug притупляет ревью).

**Фикс:** убрать `Display` либо сделать его тоже redacted, а сериализацию для bridge-line/statefile вынести в явные `to_bridge_arg()`/`to_hex()` методы, чтобы поверхность вывода секрета была греппаемой.

### GLMS-05 — P3 — ошибка парсинга `TOR_PT_PROXY` несёт URI с учётными данными

**Где:** `crates/core/src/helpers.rs:203-204`:

```rust
let uri = Url::parse(&url_str)
    .map_err(|e| to_io_other(format!("failed to parse proxy config \"{url_str}\": {e}")))?;
```

**Механизм:** `url_str` — сырой `TOR_PT_PROXY` вида `socks5://user:pass@10.0.0.1:1080`; при невалидном URI он целиком (включая пароль) попадает в текст ошибки → в логи через любые верхнеуровневые `error!/warn!`. Новый путь lyrebird не задет — ветка перевела его на `ClientInfo::without_proxy()` + `Proxy::parse` с `Err(())` без значений (proxy.rs) и `print_proxy_error("invalid or unsupported upstream proxy")` — это правильный паттерн. Но `ClientInfo::new()` остаётся публичным API core для других потребителей.

**Фикс:** не включать `url_str` в сообщение (или только scheme/host); пароль никогда.

### GLMS-06 — P3 — новый dependency `resocks5-net 0.4.1`: реализация недоверенного ответа прокси локально не верифицирована

**Где:** Cargo.lock ветки: registry-источник, checksum `ccc6546974…`, deps `base64`, `socket2`, `tokio`. Минимальное дерево — хорошо; base64 в deps подтверждает, что HTTP Basic кодируется (CRLF-инъекция через credentials в заголовок невозможна). Но сам код `socks5_handshake` / `http_connect_handshake` (границы чтения ответа прокси, обработка REP-кодов, лимиты auth-полей, поведение при частичном ответе) недоступен локально для ревью — это новая поверхность, где недоверенный пир = upstream-прокси. Задача таймаута решена снаружи (`proxy.rs:9` CONNECT_TIMEOUT 10 c через `timeout_at`), лимит размера ответа прокси — внутри крейта, не проверен.

**Фикс/обязательство:** в CI — `cargo audit`/`cargo deny` + ревью исходника крейта 0.4.1 (границы чтения заголовков CONNECT-ответа, whitelist REP-кодов, отсутствие неограниченного `read_line`); пин точной версии уже в lock. До этого считать «поведение при злонамеренном upstream-прокси не верифицировано».

### GLMS-07 — P3 — `unwrap()` на `to_representative` в `From<&EphemeralSecret>`

**Где:** `crates/obfs4/src/common/x25519_elligator2.rs:150-155`:

```rust
fn from(secret: &'a EphemeralSecret) -> PublicRepresentative {
    let res: Option<[u8; 32]> =
        Randomized::to_representative(secret.0.as_bytes(), secret.1).into();
    PublicRepresentative(res.unwrap())
}
```

**Механизм:** ~50% случайных ключей не имеют elligator2-представителя; паника достижима только для `EphemeralSecret`, собранного вне `Keys::{random_ephemeral, ephemeral_from_rng}` (они re-roll до успеха). Конструктор `from_parts` — `cfg(test)`. Сегодня инвариант держится типовой дисциплиной конструирования, а не типом (§B5: инвариант должен переживать весь safe-API модуля; `Clone` на `EphemeralSecret` позволяет тиражировать пары, но не создаёт невалидных).

**Фикс (когда удобно):** вернуть `Result` из `From` или завести проверяющий конструктор; не критично.

## Что проверено и чисто (позитивная assurance)

- **§B24**: все сравнения MAC/mark/seed/cookie — `ct_eq`/`subtle` (handshake_client.rs:110,218; handshake_server.rs:288; drbg.rs:34-37; orport.rs:19); сервер всегда исполняет DH+derive до reject non-contributory (handshake_server.rs:110-132) — нет раннего выхода; ошибки аутентификации не различаются наружу (единый `BadClientHandshake`; `ReplayedHandshake` различим намеренно, документировано и соответствует Go-референсу). `Proxy::connect` все отказы сводит к одному «upstream proxy connection failed» (proxy.rs:152-154) — без оракула.
- **Nonce policy**: XSalsa20-Poly1305 nonce = префикс(16)+счётчик(8), старт 1, детект wrap → fatal (codecs.rs:454-476); энкодер/декодер раздельные. По спецификации obfs4 (совместимость с Go).
- **RNG**: prod-ключи — OS-entropy (`getrandom`, `StaticSecret::random*`, `Seed::new`); test-only фиксированные сиды изолированы; `fake_prng` в test_utils. rand ≥ 0.8.8/0.9.5/0.10.2 — RUSTSEC-2026-0097 закрыт.
- **§B7**: frame length clamp до reserve (codecs.rs:226-247, max 1446); messages_v1 точные length-проверки + T2-регрессии и proptest `try_parse_never_panics`; handshake-чтение в фиксированный `[u8; 8192]` (sessions.rs:275,509) с bound-условием full-buffer; DoH/CONNECT-ответы ограничены (webtunnel handshake.rs:565-571 — 4 KiB cap); replay-фильтр ограничен (MAX_FILTER_SIZE 100*1024, evict); рекурсивных парсеров нет.
- **§B5/§B18/§B25**: весь `unsafe` — только `stdin_watch.rs` (unix/windows), каждый блок с `// SAFETY:`; новое изменение `AsyncFd::register_with_interest` (stdin_watch.rs:74-76) sound: дублированный OwnedFd уникально владеется и мувается в AsyncFd, закрывается только им; `assume_init` после успешного `fstat`; `GetLastError` читается сразу после вызова. `unsafe impl Send/Sync`, `transmute`, `from_raw_parts`, `mem::uninitialized/zeroed`, `#[no_mangle]`, `extern "C"` — отсутствуют по всему репо.
- **TLS (webtunnel)**: webpki-roots, дефолтная верификация, resumption disabled, ALPN пуст (camouflage, соответствует Go); `danger_accept_invalid_*`/кастомный `ServerCertVerifier` — отсутствуют по всему дереву; SNI валидируется `ServerName::try_from` на prepare (lib.rs:283-284).
- **PT-spec прокси-гейт**: fail-closed — невалидный/неподдерживаемый `TOR_PT_PROXY` → `PROXY-ERROR` до биндинга листенеров (lib.rs client_setup); `PROXY DONE` только при валидном прокси; носитель всегда через прокси, фолбэка на прямой диал нет (impl ManagedClient для obfs4/webtunnel).
- **Credentials**: `Proxy` без `Debug`-derive («never log its fields»); `configure_builder` ошибки без значений; HTTP-Basic colon-rejoin (`http_credentials`, connection.rs:104) корректен; percent-decoded CR/LF в HTTP-credentials отвергаются `is_ascii_control` (proxy.rs:80-81) с негативным тестом `p%0A`; SOCKS5-поля ≤ 255 (RFC 1929).
- **§B14**: accept-loop ограничен семафором (connection_permit, lib.rs:651-661), transient/fatal классификация ошибок accept с джиттер-бэкоффом.
- **§C2/прочее**: Command-инъекций нет (процессов не спавнит); statefile — tempfile 0o600 на unix + atomic rename (obfs4 lib.rs:230-263); state-dir 0o700 (core helpers.rs:86); accept-retry без переполнения; cancel-safety аннотации на местах (proxy.connect «NO», Prefixed/copy paths).

## Threat model-ограничения (что недоверенно / доверено / не верифицировано)

- **Недоверенно**: сетевой ввод peer'ов (obfs4-фреймы, ntor-хендшейк, webtunnel HTTP-ответ, SOCKS5-запросы родителя, ответы upstream-прокси); bridge-line аргументы (`url=`, `addr=`, `cert=`, `servername=`) — полу-доверенные (дистрибьютор мостов); PT-родитель (tor/arti) — доверенный, но его `target_addr` на obfs4-пути нормализуется в IP-литерал до `proxy.connect`.
- **Доверенно**: конфигурация из env (`TOR_PT_*`), statefile/identity пути (оператор), upstream-прокси — **полу-доверенный**: видит цели CONNECT (инherent к TOR_PT_PROXY), его ответы парсит внешний крейт (см. GLMS-06).
- **Не верифицировано**: реализация `resocks5-net` 0.4.1 (bounds ответов, REP-коды); достижим DoH-пул в сети (SNI GLMS-03 — механизм подтверждён локально, фактические имена сертификатов провайдеров не запрашивались); `cargo audit` не запускался по правилам аудита — advisory-статус остальных пинов (hickory 0.26.2, crypto_secretbox 0.1.1 и пр.) не проверен; interop с Go-референсом — по тест-векторам в репо (Hash-DRBG/ntor), живого interop-прогона не было; Windows-ACL statefile (unix-mode только на unix).
- Отсутствующие threat models зафиксированы как находки, не как блокировка: формального документа «кто атакующий на каждом хопе» в репо нет; выводы выше опираются на PT-spec и README угрозы (censorship observer, malicious bridge distributor — принят по задаче).

## Что не проверено

- `crates/obfs4/src/server.rs`/`proto.rs` (server accept path, IAT, close-delay) — вне заявленного приоритетного списка, проверены только места, куда ведёт поток данных из аудируемых модулей (handshake bounds, replay TTL).
- `crates/bridge-line` (парсер мост-линий) и `crates/ptrs-gesher` (umbrella) — не входили в срез.
- Cargo.lock-пины не прогнаны через advisory-базу (cargo запрещён правилами задачи).
