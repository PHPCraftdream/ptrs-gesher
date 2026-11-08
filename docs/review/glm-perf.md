# GLM-ревью производительности — 2026-11-05

Срез: HEAD `b8982e3` (ветка `socks-carrier-160-20261104`) + diff vs main: новые `crates/lyrebird/src/client/proxy.rs` (371 строка) и `crates/lyrebird/src/client/connection.rs` (194 строки), переработан `crates/lyrebird/src/lib.rs`, точечные правки `pt_proto.rs`, `stdin_watch.rs`, `crates/webtunnel/src/lib.rs` (+7), `crates/core/src/helpers.rs` (+13). Аудит статический, read-only: cargo не запускался (по условию). Production-код не редактировался.

Методика: rust-intel §E1 (serialism), §E2 (аллокации), §E3 (O-сложность), §E4 (contention), §E5 (lazy-инициализация), §E6 (measure first), §C4 (итерации/буферы). Substitution catalog применён как каталог предложений, не мандат.

## Версии (Cargo.lock @ b8982e3, resolved)

| Крейт | Версия |
|---|---|
| tokio | 1.54.1 |
| tokio-util | 0.7.19 |
| bytes | 1.12.1 |
| crypto_secretbox | 0.1.1 |
| rustls | 0.23.46 |
| resocks5-net | 0.4.1 |
| percent-encoding | 2.3.2 |
| url | 2.5.8 |
| socket2 | 0.6.5 |
| siphasher | 1.0.3 |
| getrandom | 0.2.17 / 0.3.4 / 0.4.3 (три мажора в графе) |
| criterion | 0.5.1 |
| anyhow | 1.0.104 |
| tracing | 0.1.44 |
| x25519-dalek / curve25519-dalek | 2.0.1 / 4.1.3 |
| sha2 | 0.10.9 |

## Сводка

| ID | P | Область | file:line | Находка |
|---|---|---|---|---|
| GLMP-01 | P2 | obfs4 codec, приём | crates/obfs4/src/framing/messages_v1/mod.rs:119 | `let mut dst = vec![]` без `with_capacity(length)` — ~6–8 реаллокаций роста на каждый принятый payload-кадр |
| GLMP-02 | P2 | лог-диспетчер, релей | crates/lyrebird/src/logging_layer.rs:149,299 | `Interest::sometimes()` для всех callsites + `max_level_hint() -> None` + RwLock-чтение на каждый `enabled()` — per-frame `trace!`/`debug!` платят диспетчеризацию даже на уровне ERROR |
| GLMP-03 | P3 | obfs4 codec, приём | crates/obfs4/src/framing/codecs.rs:265 | лишняя полнокадровая копия `src → scratch` перед in-place расшифровкой (можно дешифровать прямо в `src`) |
| GLMP-04 | P3 | obfs4 TX, length padding | crates/obfs4/src/common/probdist.rs:60-64 | `getrandom` syscall + uncontended Mutex на каждый `sample()` — вызывается на каждый `poll_write` |
| GLMP-05 | P3 | lyrebird proxy, HTTP-носитель | crates/lyrebird/src/client/proxy.rs:126-133 | 3 клона/аллокации на соединение (`ip().to_string()`, `user.clone()`, `password.clone()`) — навязаны API resocks5-net `ProxyConfig` |
| GLMP-06 | P3 | lyrebird dial | crates/lyrebird/src/lib.rs:407,788 | `resolve_target_addr(impl Display)` форсирует `.to_string()` копию уже принадлежащего `String` на каждое соединение |
| GLMP-07 | P3 | webtunnel + proxy | crates/webtunnel/src/lib.rs:479-481 | `carrier_destination()` перезапускает полный re-parse URL (`PreparedConfig::new`) на каждое проксируемое соединение |

Итого: **P0: 0; P1: 0; P2: 2; P3: 5**.

Правила Tier E соблюдены: ни одна находка не P0/P1. Механизмы P2 доказуемы статически; масштаб эффекта всех находок, где это не асимптотика, помечен «требует бенчмарка (§E6)».

## Находки

### GLMP-01 — P2: `vec![]` без capacity на пути приёма каждого payload-кадра

Место: `crates/obfs4/src/framing/messages_v1/mod.rs:119`

```rust
MessageTypes::Payload => {
    let mut dst = vec![];
    ...
    dst.put(buf.take(length));
```

**Механизм.** Это ветка `Messages::try_parse`, вызываемая из `EncryptingCodec::decode` на каждый принятый кадр с данными (payload ≤ `MAX_MESSAGE_PAYLOAD_LENGTH` ≈ 1427 B). `impl BufMut for Vec<u8>` в bytes 1.12 при исчерпании capacity вызывает `reserve(64)` — рост с нуля даёт ~6–8 реаллокаций (64→128→…→2048) и ~2× лишних memcpy на кадр вместо одной точной аллокации. Систематическое аллокационное давление на горячем пути приёма — P2 по критерию Tier E.

**Фикс.** `length` уже валидирован (`buf.remaining() < length` → `InvalidMessage`; remaining ограничен размером кадра):

```rust
let mut dst = Vec::with_capacity(length);
```

(или `vec![0u8; length]` + `copy_to_slice`). Покрыто существующим бенчем `obfs4_bench` группа `codec/decode` и `roundtrip` — эффект измерим сразу; для фиксации счётчика аллокаций добавить dhat/alloc-counter проверку (§E6, детерминированный счётчик).

### GLMP-02 — P2: лог-диспетчер платит полную проверку на каждый per-frame `trace!`/`debug!`

Места: `crates/lyrebird/src/logging_layer.rs:149` (`Interest::sometimes()`), `:299` и `:431` (`max_level_hint() -> None`), `:152-166` (`enabled`), `:168-176` (`event_enabled`), `:180` (`on_event`).

```rust
fn register_callsite(&self, ...) -> tracing::subscriber::Interest {
    ...
    tracing::subscriber::Interest::sometimes()
}
...
fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
    None
}
...
fn enabled(&self, metadata, ctx) -> bool {
    let filter = self.new_span_filter(&ctx);      // RwLock read + Arc clone
    let enabled = filter.enabled(metadata, ctx.clone());  // EnvFilter eval
    enabled && self.inner.read()...               // второй RwLock read + dyn dispatch
}
```

**Механизм.** `OwnedDispatcher` — прод-путь lyrebird (`run()` ставит его при отсутствии чужого subscriber). `Interest::sometimes()` возвращается безусловно, `max_level_hint() -> None` лишает tracing-core статической отсечки: каждый `trace!`/`debug!` callsite проходит `Dispatch::enabled()`. Codec эмитит 3–5 лог-вызовов на кадр в каждую сторону (`trace!` входа/длимаски/нонса, `debug!` результата в `codecs.rs`, `trace!` в `try_parse`). Итого на кадр: ~6–10 × (2 acquire RwLock + Arc-рефкаунт + `EnvFilter::enabled` + dyn-dispatch через `Box<dyn Layer>`), даже когда фильтр ERROR всё отсекает и форматные аргументы (слава ленивости макросов) не вычисляются. Это сопоставимо по порядку с самой AEAD-операцией кадра — систематическая нагрузка на релейном пути.

**Фикс (эскиз, с сохранением hot-reload фильтра):**

1. `max_level_hint()` → `Some(self.inner.read().ok().map(|l| l.filter.max_level_hint()).unwrap_or(LevelFilter::OFF))` — tracing-core сам выдаст `Interest::NEVER` callsites выше максимума и перестанет звать `enabled()` для `trace!`/`debug!` на дефолтном ERROR.
2. В `enabled()` использовать thread-local кэш `Arc<EnvFilter>` (уже существующий `BOUND_FILTER`) вместо чтения `RwLock` на каждый вызов; инвалидиция — по поколению/generation counter, обновляемому при reload.
3. `register_callsite` может возвращать Interest от `EnvFilter::register_callsite` (NEVER для непроходящих) — существующий цикл перерегистрации callsites при reload (`lib.rs:316-325`) уже перекладывает новый Interest.

Масштаб выигрыша — требует бенчмарка (§E6): бенч decode/encode без subscriber есть, с установленным OwnedDispatcher — нет (см. «Бенчмарки»).

### GLMP-03 — P3: лишняя полнокадровая копия перед расшифровкой

Место: `crates/obfs4/src/framing/codecs.rs:265`

```rust
dec.scratch.clear();
dec.scratch.extend_from_slice(&src[..next_len]);
... decrypt_in_place_detached(..., &mut dec.scratch[TAG_SIZE..], &tag)
```

**Механизм.** Весь кадр (до 1448 B) копируется из `src` в `scratch` для in-place расшифровки, затем plaintext ещё раз копируется в owned `Vec` в `try_parse` (GLMP-01). Слой NaCl secretbox — `[tag(16) || ciphertext]` — непрерывен внутри `src[..next_len]`, поэтому можно расшифровывать прямо в `src`: `decrypt_in_place_detached(nonce, b"", &mut src[TAG_SIZE..next_len], &tag)`, затем `src.advance(next_len)` и парсить из `src`. Экономия: одна полнокадровая memcpy на каждый принятый кадр плюс per-connection `scratch` (1448 B). Замечание: при несовпадении тега текущий код не потребляет `src` — при расшифровке на месте буфер будет частично перезаписан, но любой tag mismatch фатален для сессии (комментарий в коде это фиксирует), наблюдаемое поведение не меняется. Требует бенчмарка (§E6) — покрыто группой `codec/decode`.

### GLMP-04 — P3: syscall `getrandom` на каждый `poll_write` ради length padding

Место: `crates/obfs4/src/common/probdist.rs:60-64`

```rust
pub fn sample(&self) -> i32 {
    let mut buf = [0_u8; 16];
    getrandom::getrandom(&mut buf).expect(...);
    let dist = self.0.lock().unwrap();
```

**Механизм.** `O4Stream::poll_write` вызывает `length_dist.sample()` на каждый чанк записи (IAT Off тоже), плюс `iat_dist.sample()` при IAT ≠ Off. Каждый `sample()` — OS CSPRNG syscall (на Windows ProcessPrng) + uncontended `Mutex`. Это соответствует референсу Go (csrand на каждый сэмпл) и существующий бенч `weighted_dist_sample` = 255 ns честно включает syscall. Замена на session-scoped CSPRNG (ChaCha, засеянный из OS) устранила бы syscall с горячего пути, но меняет источник энтропии длины пединга — крипторелевантное решение (§B12): требует отдельного согласования и бенчмарка на tunnel-throughput (§E6), не «просто оптимизация». Lock вне hot contention (per-connection dist), оставлен как есть.

### GLMP-05 — P3: клоны на соединение в HTTP-ветке `Proxy::connect`

Место: `crates/lyrebird/src/client/proxy.rs:126-133`

```rust
let mut config = ProxyConfig::new(
    ProxyProtocol::Http,
    self.address.ip().to_string(),   // аллокация
    self.address.port(),
);
if let Some((user, password)) = &self.credentials {
    config.user = Some(user.clone());       // аллокация
    config.password = Some(password.clone()); // аллокация
}
let target = HostPort::format(host, port);  // аллокация
```

**Механизм.** 3–5 аллокаций на каждое соединение через HTTP-носитель. Per-connection, не per-packet — холоднее P2-порога. SOCKS5-ветка чиста (`socks5_handshake(..., auth: Option<(&str, &str)>)`). Клоны навязаны owned-полями `ProxyConfig` в resocks5-net 0.4.1 — без изменения upstream API не убираются; можно убрать только `self.address.ip().to_string()` (кэшировать IP-строку в `Proxy` при `parse`). Низкий приоритет; фикс в upstream — отдельная задача вне этого репо.

### GLMP-06 — P3: лишний `to_string()` в `resolve_target_addr`

Места: `crates/lyrebird/src/lib.rs:407` (реализация), `:788` (вызов с уже owned `String`).

```rust
pub fn resolve_target_addr(addr: impl std::fmt::Display) -> Result<SocketAddr> {
    ptrs::resolve_addr(addr.to_string()).context("PT target must be an IP address")
}
...
let remote_addr = resolve_target_addr(&target_addr).context("no remote address")?;
```

**Механизм.** `impl Display` + `.to_string()` копирует `String`, которым вызывающий уже владеет: +1 аллокация на соединение. Фикс — принять `&str` (или перегрузку), внутренний parse всё равно требует `&str`. Покрыто бенчами `resolve_target_addr_*` (lyrebird_bench). Тривиально, per-connection — P3.

### GLMP-07 — P3: `carrier_destination()` повторно валидирует URL на каждое соединение

Место: `crates/webtunnel/src/lib.rs:479-481` → `PreparedConfig::new` (`:244-...`)

```rust
pub fn carrier_destination(&self) -> Result<(String, u16), Error> {
    let prepared = self.config.as_ref().ok_or(Error::MissingUrl)?.prepare()?;
    Ok((prepared.host, prepared.port))
}
```

**Механизм.** `prepare()` = полный `url::Url::parse` + разбор `addr=`/`servername` на каждое проксируемое webtunnel-соединение, хотя `WebTunnelConfig::from_args` уже валидировал то же самое при старте. Per-connection стоимость микросекундного масштаба — P3. Фикс: кэшировать `PreparedConfig` в `WebTunnelClient` (или `Arc` в билдере) после первой успешной подготовки; попутно убирает и повторный `prepare()` в `connect_url`.

## Возможности ускорения (по ожидаемому эффекту)

1. **GLMP-01** — приём: с ~6–8 аллокаций + ~2× memcpy на payload-кадр до 1 аллокации. Оценка: −5–7 аллокаций/кадр RX; измеримо в `codec/decode`.
2. **GLMP-02** — релей: −6–10 диспетчеризаций лог-вызовов на кадр (×2 направления), каждая ~100–300 ns (2 RwLock + EnvFilter + dyn). Оценка при ERROR: сотни нс/кадр; требует бенчмарка с установленным subscriber (§E6).
3. **GLMP-03** — приём: −1 полнокадровая memcpy (до 1448 B) на кадр RX + −1448 B/соединение памяти. Требует бенчмарка.
4. **GLMP-04** — передача: −1 syscall (до ~150–250 ns) на `poll_write`. Требует бенчмарка tunnel-throughput + крипто-согласования.
5. **GLMP-05/06/07** — по 1–5 аллокаций/re-parse на соединение; эффект виден только при высоком rate новых соединений.

Позитив (уже сделанные оптимизации, сохранены в ветке): zero-copy `PayloadFrame`/`PaddingFrame` на encode (буфер не копируется в staging), in-place AEAD в обе стороны, нонс собирается на стеке (`NonceBox::next`), переиспользуемый `scratch` декодера, session-fixed cipher (`SecretBox` с zeroize), `Prefixed` отдаёт prefix без копий, `copy_bidirectional` — стандартный tokio, `ReplayFilter` — O(1) HashSet+VecDeque. `Regex`/парсеров в горячих функциях нет (§E5 чисто). Последовательных `.await` независимых операций не найдено (§E1 чисто: все цепочки `Proxy::connect`/handshake причинно-зависимы).

## Бенчмарки: покрытие находок

| Находка | Покрыта? | Где / что добавить |
|---|---|---|
| GLMP-01 | Да | `obfs4_bench` группы `codec/decode`, `roundtrip`; добавить изолированный `Messages::try_parse` bench + dhat-счётчик аллокаций на кадр (детерминированный счётчик, §E6) |
| GLMP-02 | Нет | Добавить вариант `codec/decode` с установленным OwnedDispatcher на уровне ERROR (сравнить с без-subscriber) |
| GLMP-03 | Да | `codec/decode` покажет выигрыш; dhat-счётчик байт-копий усилит |
| GLMP-04 | Частично | `weighted_dist_sample` (255 ns) фиксирует unit-cost; tunnel-эффект — `throughput_bench` IAT Off vs будущий CSPRNG-вариант |
| GLMP-06 | Да | `resolve_target_addr_*` в `lyrebird_bench` |
| GLMP-05, GLMP-07 | Нет | Per-connection, холодный путь — бенч не обязателен |
| Новое в ветке: `Prefixed` | Нет | Добавить read-bench `Prefixed` поверх duplex (prefix → inner переход) |
| Новое в ветке: `Proxy::parse` | Нет | Опционально: parse-bench (вызов 1 раз/процесс, низкий приоритет) |
| Новое в ветке: relay e2e | Частично | `bidirectional_copy` в `lyrebird_bench` покрывает копирование, но не через `Prefixed`/SOCKS-слои |

## Что не проверено

- Ничего не исполнялось: cargo (build/check/test/bench) не запускался по условию; все оценки — статический анализ. Масштаб эффектов GLMP-02/03/04 — требует бенчмарка (§E6).
- Внутренности `resocks5-net` 0.4.1 (`socks5_handshake`, `http_connect_handshake`, `server::accept`, `HostPort::format`) не аудировались — per-connection аллокации внутри зависимости вне среза.
- Ветка IAT `Paranoid` (`proto.rs`) просмотрена статически; временны́е характеристики delay-цикла не оценивались.
- Server-путь `experimental-server` (`server.rs`, `crates/core` orport/passthrough) — вне приоритетов брифа; просмотрен только grep'ом (антипаттернов не найдено).
- Windows-специфика `getrandom` (ProcessPrng) vs Linux `getrandom(2)` — стоимость syscall платформозависима; числовые оценки GLMP-04 даны для ориентира.
- Дублирование трёх мажоров `getrandom` (0.2/0.3/0.4) в графе — замечено, к перформансу отношения не имеет (унаследовано зависимостями), не разбиралось.
- `crates/bridge-line`, `crates/ptrs-gesher` (umbrella) — только поверхностный осмотр: parse-пути стартовые, hot-кода нет.

Итог: **P0: 0; P1: 0; P2: 2; P3: 5**.
