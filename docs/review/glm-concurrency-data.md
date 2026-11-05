# GLM-ревью конкурентности и данных — 2026-11-05

Срез: HEAD `b8982e3fff90af3c0c76ccfabda0c7e8b04cec28` (ветка `socks-carrier-160-20261104`), diff vs `main`. Новое: `crates/lyrebird/src/client/{proxy,connection}.rs`, переработанный `lib.rs` + `lifecycle.rs`, `stdin_watch.rs` (unsafe-регистрация AsyncFd), `webtunnel::carrier_destination`, `core::ClientInfo::without_proxy`. Методика: rust-intel `concurrency-and-state.md` (§A2, §B9, §B10, §B13, §B14, §B17, §B19, §C8, §E4) + `data-and-types.md` (§B6, §B16, §B20, §B26–§B29, §C4) + SKILL.md (Enforcement tiers). Аудит статический, read-only; cargo не запускался, production-код не редактировался.

Шкала: P0 — критическая; P1 — высокая; P2 — обычный цикл; P3 — ограниченное влияние. Статус находок: **открыта**.

## Сводка

| ID | P | Область | file:line | Находка |
|---|---|---|---|---|
| GLMC-01 | P3 | Lyrebird logging | crates/lyrebird/src/lib.rs:264-281, 338-348 | §B13 TOCTOU: проверка режима safelog и `active_guards += 1` в разных критических секциях; check-then-act вокруг `set_global_default` |
| GLMC-02 | P3 | Lyrebird logging | crates/lyrebird/src/lib.rs:222-231 | §B17 непоследовательная политика отравления: `LoggingGuard::drop` молча пропускает декремент при poisoned lock |
| GLMC-03 | P3 | Lyrebird logging | crates/lyrebird/src/lib.rs:282-349 | §B11/§E4: блокирующий file I/O (`OpenOptions…open`) под мьютексом `LOGGING_STATE` внутри async `run()` |

Итого: **P0: 0; P1: 0; P2: 0; P3: 3**. Целевые проверки §B13 Relaxed-publish, §B14 attacker-extendable коллекций и §B26 narrowing на trust boundary нарушений не выявили (см. «Проверено — нарушений не подтверждено»). Это не заключение об отсутствии дефектов во всех конфигурациях.

## Находки

### GLMC-01 — P3: init_logging_recvr — split critical sections (§B13)

Места: [проверка режима](../crates/lyrebird/src/lib.rs#L264), [foreign-subscriber](../crates/lyrebird/src/lib.rs#L271), [инкремент в чужой ветке](../crates/lyrebird/src/lib.rs#L275), [set_global_default + регистрация](../crates/lyrebird/src/lib.rs#L338-L348).

```rust
let state = logging_state().lock()...;
if state.active_guards > 0 && state.mode != Some(mode) { ... Err ... }
drop(state);                                   // окно 1
if foreign_subscriber_installed() { ... }      // повторный lock внутри
...
if let Err(error) = tracing::subscriber::set_global_default(subscriber) { ... } // окно 2
...
state.active_guards += 1;
state.mode = Some(mode);
```

**Механизм.** Проверка «нельзя менять safelog-политику при активном run» и инкремент счётчика — две раздельные критические секции. Два параллельных `run()`/`run_from_env()` (библиотечный embedding, публичный API) с разными `unsafe_logging` оба проходят проверку, пока `active_guards == 0`, и оба инкрементируют; итоговый `state.mode` зависит от порядка. Второе окно: между `foreign_subscriber_installed() == false` и `set_global_default` третья сторона может установить своего subscriber — тогда ветка уходит в `tracing::debug!`-fallback, но всё равно делает `active_guards += 1` и `mode = Some(...)` для subscriber, которым не владеет: логи идут чужому подписчику, а state утверждает, что наш режим активен.

**Сценарий отказа.** Embedder запускает два PT-инстанса в одном процессе (разные statedir). Второй с иным log-level/safelog не получает отказа «cannot change safelog policy while a run is active», хотя контракт проверки это предполагает; при совпадении с окном `set_global_default` логи второго инстанса направляются не в его фильтр. Ошибки ввода-вывода/контента нет — рассинхрон lifecycle-учётa логирования.

**Граница.** Оба входа документированы как «эксклюзивный доступ до возврата» (docs `run()`), поэтому параллельный вызов — злоупотребление контрактом; влияние ограничено подсистемой логирования. Прод-путь один `run()` на процесс.

**Исправление.** Провести «проверка режима → решение о subscriber → инкремент» под одним захватом `LOGGING_STATE`, а установку subscriber выполнять между lock-секциями с повторной валидацией после `set_global_default` (или перевести решение на CAS-подобный протокол: занимать слот `active_guards` до установки). Regression-тест: два потока вызывают `init_logging_recvr` с разными режимами — ровно один получает Ok.

### GLMC-02 — P3: LoggingGuard::drop молча теряет декремент при poisoned lock (§B17)

Место: [Drop для LoggingGuard](../crates/lyrebird/src/lib.rs#L222-L231).

```rust
impl Drop for LoggingGuard {
    fn drop(&mut self) {
        self.guard.take();
        if let Ok(mut state) = logging_state().lock() {
            state.active_guards = state.active_guards.saturating_sub(1);
            if state.active_guards == 0 { state.mode = None; }
        }
    }
}
```

**Механизм.** Если `LOGGING_STATE` отравлен (паника другого потока под этим же мьютексом, например в `init_logging_recvr` при построении слоёв), `if let Ok` молча пропускает декремент: `active_guards` навсегда остаётся > 0, `mode` — застывшим. Все последующие `init_logging_recvr` с другим режимом получают постоянный отказ «cannot change safelog policy while a run is active» — клин без диагностики. Политика отравления внутри того же файла непоследовательна: чтение state использует `map_err(|_| anyhow!("logging state lock poisoned"))`, а соседний `ManagedLayer::register_callsite` (logging_layer.rs:138-141) и `ReplayFilter::test_and_set` (replay_filter.rs:39-44) восстанавливают guard через `into_inner()`.

**Сценарий отказа.** Паника в потоке, удерживающем `LOGGING_STATE` (например, в closure слоя логирования) → завершившийся run оставляет `active_guards = 1` → повторный `run()` в том же процессе навсегда отклоняется по режиму, без единого упоминания отравления в логах.

**Исправление.** Единая политика: `let Ok(mut state) = ... else { log/repair }` с `unwrap_or_else(|p| p.into_inner())` (данные — три скаляра, целостность после паники не критична), либо явная диагностика в ветке Err. Согласовать с существующим `map_err(poisoned)` в том же файле.

### GLMC-03 — P3: блокирующий file I/O под мьютексом в async-контексте (§B11/§E4)

Место: [lock](../crates/lyrebird/src/lib.rs#L282), [open файла](../crates/lyrebird/src/lib.rs#L298), [release](../crates/lyrebird/src/lib.rs#L349).

```rust
let mut state = logging_state().lock()...;      // 282: lock захвачен
...
let file = std::fs::OpenOptions::new()          // 298: блокирующий open
    .create(true).append(true)
    .open(format!("{statedir}/obfs4proxy.log"))?;
...
state.active_guards += 1;                        // 347
drop(state);                                     // 349
```

**Механизм.** `init_logging_recvr` — синхронная функция, вызываемая из async `run()`; под std-мьютексом выполняется `std::fs::open` (и `std::env::var_os`). На пути setup до первого `.await` это не блокирует executor надолго, но: (а) токийский воркер выполняет blocking syscall; (б) секция «lock → open → регистрация callsites → write конфигурации» удлиняет критическую секцию, которуюhot-путь логов (`ManagedLayer::enabled`/`on_event` через `inner.read()`) ждёт при reload-конфликте.

**Сценарий отказа.** Медленный/перегруженный ФС (сетевой диск, антивирусный фильтр на Windows) растягивает open на сотни мс: setup-часть `run()` держит воркер и `LOGGING_STATE`; параллельный embedding-код, логирующий в этот же процесс, стоит на reload-пути. Единичный вызов на процесс — влияние ограниченное.

**Граница.** Не отмечается как §B11-дефект уровня «sleep в async fn»: вызов одноразовый, до входа в основной цикл; это гигиена критической секции.

**Исправление.** Открыть файл до захвата `LOGGING_STATE` (statedir известен), мьютекс держать только на чтение-модификацию-запись состояния; при необходимости — `tokio::task::spawn_blocking` для open с передачей `File` (impl `Send`).

## Проверено — нарушений не подтверждено

Целевые пункты задания, аудит которых дал чистый результат:

- **§B13 Relaxed-publish (🔴).** `Relaxed`-атомиков в audited-крейтах нет вообще (`git grep Relaxed` по `crates/{lyrebird,obfs4,webtunnel,core}/src` — пусто); publish-паттернов «store флага после записи payload» не найдено. `Arc::strong_count` в условиях отсутствует.
- **§B14 replay-фильтр (🔴 при attacker-extendable ключах).** `crates/obfs4/src/common/replay_filter.rs`: ключ — SipHash-2-4-digest фиксированной cardинальности (u64), не сетевой ввод; bound есть — `MAX_FILTER_SIZE = 100 * 1024` с FIFO-вытеснением (`fifo.len() >= max_cap` → `evict_oldest` до вставки, строки 108-118) плюс TTL-garbage-collect и clamp монотонности времени (`latest_time`, строки 82-89). Check-then-insert атомарны под одним `Mutex`-guard'ом; poison обрабатывается `into_inner()` с обоснованием fail-open. Ключевых HashMap/DashMap с сетевыми ключами в obfs4 server нет.
- **§B26 length-prefix во framing (🔴 на trust boundary).** `crates/obfs4/src/framing/messages_v1/mod.rs:92-141`: `buf.take(n)`-clamping закрыт явной проверкой `buf.remaining() < length` → `InvalidMessage` (регресс-тесты T2 на месте); PrngSeed требует точного `length == SEED_LENGTH`; аллокация ограничена — в `EncryptingCodec::decode` (codecs.rs:220-227) длина demask'ится и валидируется диапазоном `[MIN_FRAME_LENGTH, MAX_FRAME_LENGTH]` (≈16..1446) до `reserve`. Инвариант `MIN_FRAME_LENGTH == TAG_SIZE` гарантирует `scratch[TAG_SIZE..]` в границах. В `build_and_marshall` (messages_base.rs:44-66) `dst.put_u16(buf.len() as u16)` защищён проверкой `total_size <= MAX_MESSAGE_PAYLOAD_LENGTH` (1445 < u16::MAX) с `checked_add`; `pad_len > u16::MAX` отвергается. Расширения `u16 → usize` — widening. `NonceBox::next` (codecs.rs:445-470) проверяет `counter == u64::MAX` до инкремента — переполнения нет.
- **§B9/§B17 граф локов логирования.** Порядок `callsites → inner` соблюдён в обоих местах (lib.rs:317-333 reload; logging_layer.rs:134-150 `register_callsite`); обратного захвата нет — ABBA отсутствует. Повторных `.read()` на уже удерживаемом `RwLock` нет (guard'ы scoped и освобождаются до вложенных вызовов); `RefCell`-borrow в `ACTIVE_SPANS`/`BOUND_FILTER` не пересекаются (в `on_exit` borrow заканчивается до `borrow_mut`). Reentrancy в `sink`-вызовы не ведёт (fmt-слой/EnvFilter спаны не создают).
- **§B14 admission accept-петли.** `client_accept_loop_with_proxy` (lib.rs:685-755): permit из `Arc<Semaphore>(1024)` берётся **до** spawn и **перемещается в задачу** (`let _permit = permit;` — корректная форма); двойная re-check отмены: после выдачи permit (lib.rs:725) и после регистрации abort-хендла (lifecycle.rs:300-305) — окно «permit выдан / cancel сработал / задача заспавнена» закрыто. Accept-ошибки классифицированы (fatal → `Err`, transient → экспоненциальный backoff 50мс→1с с `saturating_mul` и ограниченным сдвигом `1u64 << min(n,5)`), включая EMFILE/ENFILE — горячего спина и гибели петли нет.
- **§B21/§B19 lifecycle.** Все spawn идут в owned `JoinSet`; `spawn_connection` под tokio-Mutex держит guard только через sync-код (`try_join_next_with_id`, без `.await` в цикле); `RunOwner::drop` — sync-abort по всем зарегистрированным `AbortHandle` + `try_lock().abort_all()` fallback; `join_connection_tasks` до `debug_assert_eq!(available_permits, MAX)` — контрольный assert отладочный, но не является защитой корректности (учёт через semaphore + join — да).
- **§B6 wildcard-arms.** `connection.rs:47` — внешний `ServerError`: явный arm `Deadline` + типизированный fallback (не silent-ignore). `messages_v1 TryFrom<u8>:62` — явный `Err(UnknownMessageType)`. `stdin_watch.rs` — внешние io-ошибки с типизацией. Wildcard'ов над crate-owned enum без обработки не найдено.
- **§B16.** Единственный ручной `PartialEq` — `drbg::Seed` через `subtle::ct_eq` (константное время, рефлексивно), `Hash` не реализован и тип ключом map не служит. `args.rs:239 sort_unstable_by` по уникальным ключам HashMap — порядок равных не нагружен. f64-ключей нет.
- **§C4.** В новом production-коде голых `read()`/`write()`-как-полный-обмен нет: SDK-переговоры и `copy_bidirectional`, в тестах `read_exact`/`write_all`. `Prefixed::poll_read` корректно отдаёт префикс частями (partial-read контракт соблюдён), границы `prefix[offset..end]` всегда в пределах.
- **§B5 (новый unsafe).** `stdin_watch.rs:76` `AsyncFd::register_with_interest` — SAFETY-комментарий присутствует и инвариант выполняется: `watched: StdinFd` владеет dup'нутым `OwnedFd`, raw value стабилен на всю жизнь `AsyncFd`; Drop восстанавливает флаги до закрытия дубликата; остальные unsafe-точки (`fcntl`, `libc::read`) покрыты комментариями.
- **§B28/§B29.** Срезов строк по вычисленным байтовым индексам в новом коде нет; `decode()` в proxy.rs проверяет hex-валидность до `percent_decode_str(...).decode_utf8()` (UTF-8 невалидность → Err); zip/chunks/windows из сетевого ввода нет; collect в HashMap с возможными дублями нет.
- **§B20.** `JsonClientState` (obfs4 client.rs): `Option<T>` + `#[serde(default)]` — коллапс null/absent допустим (оба означают «не задано», трёх-семантики не требуется); `untagged` в audited-крейтах нет; u64>2^53 через f64 не проходит.
- **§A2/§E4.** Глобал через `OnceLock` (не `Box::leak`); init-closure `logging_state()` не паникует. `Arc<RwLock<LogConfig>>` — read-mostly с wholesale-swap через `*current = log_layers` под write — выбор оправдан; hot-путь читает под `.read()` и клонирует `Arc` наружу — секции короткие.

## Что не проверено

- **Семантика внешнего SDK `resocks5-net 0.4.1`** (заменил fast-socks5): гарантия `IncomingRequest::take_pipeline()` («байты, потреблённые SDK, идут перед непрочитанным»), полнота записи в `socks5_handshake`/`http_connect_handshake`, границы разбора HTTP CONNECT, точные значения флагов `ServerOptions::new(deadline, allow_no_auth, require_password)`. Проверены только контракты на вызываемой стороне; корректность конвейера `Prefixed` зависит от этих обещаний (низкоуровневый аудит зависимого крейта — вне этого модуля, см. §A1-процедуру).
- **`experimental-server`** — feature-gated, объявлен legacy/неполным; не аудировался.
- **Криптография ntor/elligator2 и e2e-поток obfs4** — проверены только границы парсинга/длин и конкурентные структуры; математическая корректность handshake — вне среза модулей (конкурентность+данные).
- **Supply-chain** новых зависимостей (`resocks5-net`, `url`, `percent-encoding`) — §A1, другой модуль.
- Никакие сборки/тесты не выполнялись (правило задания); все выводы — статический анализ среза `b8982e3`.
