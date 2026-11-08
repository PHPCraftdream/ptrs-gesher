# GLM-ревью async — 2026-11-05

Срез: **HEAD b8982e3** (ветка socks-carrier-160-20261104), diff `main...b8982e3`. Ревью выполнялось в изолированном worktree, чей base стоял на b2f793c (до ветки 0.8.0), поэтому все новые файлы (`crates/lyrebird/src/client/proxy.rs`, `crates/lyrebird/src/client/connection.rs`, переработанный `crates/lyrebird/src/lib.rs`, `crates/lyrebird/src/stdin_watch.rs`) прочитаны через `git show b8982e3:<path>` / `git diff main...b8982e3` из общей object DB — все цитаты и file:line сверены с содержимым b8982e3.

Методика: rust-intel `async.md` — проверены §B2, §B3, §B3a, §B8, §B11, §B15a–e, §B21, §B22, §B23, §C3, §C9, §E1; калибровка приоритетов по `SKILL.md` (Enforcement tiers). Resolved-версия из Cargo.lock на b8982e3: **tokio 1.54.1** (ожидание подтверждено), rustls-webpki 0.103.16, webpki-roots 1.0.11. Runtime tokio, `cargo` не запускался (read-only аудит).

## Сводка

| ID | P | Область | file:line | Находка |
|----|---|---------|-----------|---------|
| GLMA-01 | P1 | §B14🔴 + §B21 | crates/lyrebird/src/server.rs:108, :51 | experimental-server: accept-цикл без Semaphore-cap, `tokio::spawn(server_handle_connection(...))` с отброшенным JoinHandle без `// fire-and-forget`; монитор-таск :51 — то же |
| GLMA-02 | P2 | §B3/§B11 | crates/lyrebird/src/stdin_watch.rs:19, :156, :325 | `/// cancel-safe: yes` на `wait_stdin_close` не оговорена для immediate-fd пути (регулярные файлы / нетерминальные char-устройства): блокирующий `libc::read`/`ReadFile` нельзя прервать отменой |
| GLMA-03 | P2 | §B3 (REQUIRED) | crates/webtunnel/src/lib.rs:512–541, handshake.rs:545–575 | у `WebTunnelClient::{establish, wrap}` и `upgrade_with_stream`/`read_upgrade`, работающих под собственным `timeout_at`, нет `/// cancel-safe:` аннотаций; owned-стрим потребляется внутри отменяемого скоупа без документирования |
| GLMA-04 | P3 | §B3a | crates/lyrebird/src/lib.rs:163–172 | детерминированный exponential backoff accept-ретрая без jitter |
| GLMA-05 | P3 | §B11 | crates/lyrebird/src/pt_proto.rs:35–38; crates/lyrebird/src/lib.rs:283–289 | блокирующие `stdout().lock()+writeln!` и `std::fs::OpenOptions` в async-пути запуска (bounded, startup-only) |
| GLMA-06 | P3 | §B5-гигиена | crates/lyrebird/src/stdin_watch.rs:73–76 | переход с safe `AsyncFd::with_interest` на `unsafe { AsyncFd::register_with_interest }`: SAFETY-комментарий корректен, но мотивация выбора unsafe-API не документирована |
| GLMA-07 | P3 | §C9 (инфо) | crates/lyrebird/src/lib.rs:646, :732; lifecycle.rs:297 | tracing-спаны в крейте отсутствуют полностью: спавны без `.in_current_span()`/`.instrument()` легальны сейчас, но при добавлении спанов корреляция сломается молча |

## Находки

### GLMA-01 — P1 — experimental-server: unbounded accept + отброшенные JoinHandle

**file:line:** `crates/lyrebird/src/server.rs:108` (и `:51`, `:140`)

```rust
               tokio::spawn(server_handle_connection(
                   conn,
                   server.clone(),
                   client_addr,
               ));
```

**Механизм + сценарий отказа.** Серверный accept-цикл (`server_listen_loop`, feature `experimental-server`) спавнит таск на каждое соединение без `Arc<Semaphore>`/cap — в отличие от клиентского пути, где есть `MAX_CONCURRENT_CONNS = 1024` + `connection_permit` (lifecycle.rs:157, lib.rs:721). Атакующий, способный открыть TCP-соединения с bridge-хоста, задаёт N сам: N сокетов → N тасков → неограниченная память/файловые дескрипторы (§B14, red-ветка «unbounded accept admission, attacker-extendable»). JoinHandle отбрасывается без `.await`/`.abort()` и без комментария `// fire-and-forget: detached by design` (§B21, 🔴-правило «P1 без явного комментария»): паника таска никем не наблюдается. Отягчающее: `server_handle_connection` завершается `unimplemented!()` (:140) — каждое входящее соединение гарантированно паникует таск. Дополнительно монитор-таск `server_setup` (`:51`) тоже оставляет JoinHandle отброшенным (результат доставляется через oneshot, `let _ = tx.send(true)` на :73 с комментарием best-effort — сам send корректен по §B8, но handle-политика не оговорена).

**Смягчение:** путь задвоен под `#[cfg(feature = "experimental-server")]`, README/lib.rs трижды объявляют его «not suitable for production», обработчик не выполняет I/O.

**Фикс.** Зеркалировать клиентскую дисциплину: `Arc<Semaphore>`-cap + `acquire_owned` до спавна, permit переносить в таск; таски вести в `JoinSet` (fan-in при shutdown); у оставленных fire-and-forget спавнов проставить явный `// fire-and-forget: detached by design — …`; монитор-таск либо джойнить по JoinHandle, либо комментировать detach. Альтернатива — запретить feature в release-профилях (compile_error! при `not(debug_assertions)`).

### GLMA-02 — P2 — stdin_watch: `cancel-safe: yes` не оговорена для immediate-fd пути

**file:line:** `crates/lyrebird/src/stdin_watch.rs:19` (аннотация), `:156–164` (unix `wait_immediate`), `:325–335` (windows `wait_file`)

```rust
/// cancel-safe: yes — cancellation only drops the local descriptor/handle
/// wrapper; no read is left pending elsewhere.
pub(crate) async fn wait_stdin_close() -> io::Result<()> {
```

**Механизм + сценарий отказа.** Для pipe/socket-путей аннотация верна: `AsyncFd::async_io` cancel-safe, дубль-дескриптор с RAII-восстановлением флагов (тест `cancellation_does_not_leave_a_read_pending` это фиксирует). Но `is_immediate_fd` уводит регулярные файлы и нетерминальные char-устройства на `wait_immediate` (unix) / `wait_file` (windows): синхронный `libc::read`/`ReadFile` исполняется прямо на воркере. Пока блокирующий read не вернулся, отмена невозможна физически — `timeout`/`select!` «сработает» только после возврата из syscall; при медленном источнике (сетевой диск, FUSE) future висит неопределённо дольше любого дедлайна ожидания. Это не потеря данных, а расхождение документированной гарантии с фактической (§B3: «annotate … prove each one, not assert it»). Модульная дока частично оговаривает («can briefly block … not the managed-PT path»), но в самой `cancel-safe`-аннотации оговорки нет. Управляемый PT-путь (pipe от arti/tor) не затронут.

**Фикс.** Уточнить аннотацию: `cancel-safe: yes for pipe/socket paths; NO for immediate-fd paths (blocking read cannot be preempted — bounded by fd type)`. Либо вынести immediate-чтение в `spawn_blocking` с cooperative-прерыванием, если гарантия «отмена ≤ дедлайн» понадобится и для файлового stdin.

### GLMA-03 — P2 — webtunnel: отсутствуют cancel-safety аннотации у функций под timeout_at

**file:line:** `crates/webtunnel/src/lib.rs:512–541` (`establish`, `wrap`), `crates/webtunnel/src/handshake.rs:545–575` (`read_upgrade`)

```rust
    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(async move {
            ...
            tokio::time::timeout_at(deadline, async move {
                let io = input.await...?;
                handshake::upgrade_with_stream(io, &prepared, &self.tls).await
            })
            .await
            .map_err(|_| timeout_error())?
        })
    }
```

**Механизм + сценарий отказа.** §B3 REQUIRED: каждая async-fn, выполняющаяся под `timeout`/`select!`, обязана нести `/// cancel-safe: yes/NO`. obfs4-эквивалент документирован (`crates/obfs4/src/client.rs:446–451`, sessions.rs:189–191 — «Cancellation drops an owned stream…»), webtunnel — нет. Фактическая семантика корректна: owned carrier-стрим потребляется внутри отменяемого скоупа, таймаут = полный отказ, переиспользования частично прочитанного нет; дедлайн покрывает и dial (`input.await`), и TLS+HTTP-upgrade — абсолютный дедлайн стадии есть (§F3 clean). Но вызываемая из lib.rs:734 `select!`-arm цепочка (`managed_connect_with_proxy` → `establish_pt_conn` → `establish`) дропается при forced teardown прямо посреди TLS-хендшейка — это ровно тот случай, ради которого §B3 требует аннотацию; `read_upgrade` внутри (`write_all` + цикл `read` до httparse-Complete) без дока выглядит как candidate на not-cancel-safe (`write_all` в списке не-cancel-safe методов).

**Фикс.** Добавить в `establish`/`wrap` секцию `# Cancel safety` по образцу obfs4: «cancel-safe: NO — cancellation/timeout discards the owned carrier mid-handshake; the dial+upgrade stage is bounded by `deadline`, the stream is never reused». Для `read_upgrade` — одна строка о частичной записи запроса при отмене (соединение выбрасывается, переиспользования нет).

### GLMA-04 — P3 — детерминированный backoff accept-ретрая без jitter

**file:line:** `crates/lyrebird/src/lib.rs:163–172` (`accept_retry_delay`), используется на :702–712

```rust
fn accept_retry_delay(consecutive_failures: u32) -> std::time::Duration {
    let factor = 1_u64 << consecutive_failures.min(5);
    std::time::Duration::from_millis(
        ACCEPT_RETRY_BASE_MS.saturating_mul(factor).min(ACCEPT_RETRY_MAX_MS),
    )
}
```

Механизм §B3a: детерминированный `BASE * 2^attempt` без jitter синхронизирует ретраящие инстансы в lockstep-волны после общего blip (EMFILE/ENFILE на хосте с несколькими PT-процессами). Здесь масштаб мал (один процесс, ≤2 листенера, cap 1s, отмена во сне обрабатывается `select!`-ом на :707) — поэтому P3. Фикс: добавить decorrelated jitter (рандомизация в пределах окна задержки) при случае.

### GLMA-05 — P3 — блокирующие std::io/std::fs вызовы в async-пути запуска

**file:line:** `crates/lyrebird/src/pt_proto.rs:35–38` (`emit`), `crates/lyrebird/src/lib.rs:283–289` (`init_logging_recvr`, `std::fs::OpenOptions`)

`emit` делает `std::io::stdout().lock()` + `writeln!` из async `client_setup`/`run_managed`; лог-файл открывается `std::fs::OpenOptions` в async `run()`. Записи в контрольный pipe протокола PT при переполнении буфера канала (64К, родитель не читает) блокируют воркер; открытие файла — блокирующий syscall на старте. Объёмы — единичные строки, путь — startup-only до спавна листенеров; поэтому P3, не P2. Фикс по желанию: `tokio::io::stdout()`/`tokio::fs` или перенос в `spawn_blocking` при появлении объёмного протокольного вывода.

### GLMA-06 — P3 — переход на unsafe `AsyncFd::register_with_interest` без мотивировки

**file:line:** `crates/lyrebird/src/stdin_watch.rs:73–76`

```rust
        // SAFETY: `watched` owns a duplicated descriptor that stays open, and
        // `as_raw_fd` returns the same value, for the whole life of `async_fd`.
        let async_fd = unsafe { AsyncFd::register_with_interest(watched, Interest::READABLE)? };
```

SAFETY-доказательство соответствует контракту tokio: дескриптор свежий (`F_DUPFD_CLOEXEC`), уникально владеется, нигде более не зарегистрирован — нарушение контракта не усматривается; на раннем `?` RAII (`StdinFd::drop`) восстанавливает флаги и закрывает дубль. Замечание — гигиена §B15b/§B5: смена safe `with_interest` (основная ветка) на unsafe-синоним не обоснована в коде или commit-message телом; если причина — наблюдаемое поведение safe-варианта, оно должно быть процитировано рядом с unsafe. Фикс: комментарий «почему не `with_interest`» либо возврат на safe API.

### GLMA-07 — P3 — инфо: tracing-спанов нет вовсе (§C9 — не нарушено сейчас, хрупко в будущем)

**file:line:** `crates/lyrebird/src/lib.rs:646` (`listeners.spawn`), `:732` (`ctx.spawn_connection`), `crates/lyrebird/src/lifecycle.rs:297`

По всему дереву нет `Span`/`#[instrument]`/`.instrument` — требования §C9 «спавн с активным спаном без `.in_current_span()`» не нарушается, т.к. активных спанов нет. Корреляция сейчас только через поля `address = sensitive(client_addr)` в событиях. Фикс-обязанность на будущее: при введении пер-соединенческих спанов каждый спавн (lib.rs:646, :732, lifecycle.rs:297, server.rs:51/:108) обязан получить `.in_current_span()`/`.instrument(parent)` — иначе спаны孤儿 молча.

## Проверено, дефектов не найдено (чистые зоны)

- **§B2**: std-guard'ов через `.await` нет. `aborts: StdMutex` (lifecycle.rs) используется только в синхронных секциях без `.await` внутри guard-скоупа (spawn_connection:258–297, join_connection_tasks:344–359, RunOwner::drop:255–265); `connections` — tokio::Mutex; obfs4 `effective_configuration: Mutex` — только sync-методы билдера. Нет DashMap/scc.
- **§B22**: `RunOwner::drop` (lifecycle.rs:255–266) — только sync-операции (token.cancel, abort-handle'ы, `try_lock().abort_all()`), никакого spawn/block_on/.await; `LoggingGuard::drop` (lib.rs:230–239) — sync. Compliant.
- **§B14 (клиентский путь)**: Semaphore `MAX_CONCURRENT_CONNS = 1024`, permit берётся до спавна (lib.rs:721), double-check `accept.is_cancelled()` (:725), `wait_idle`-гейт + `debug_assert_eq!(available_permits(), MAX)` (lifecycle.rs:195). `unbounded_channel`/`FuturesUnordered`/`JoinSet`-без-гейта в клиентском пути нет.
- **§B23/§B3 (клиентский путь)**: side-эффекты после selection; losing-ветка `client_handle_connection_with_proxy` в select (lib.rs:734) — задокументированный forced teardown (`cancel-safe: NO` на connection.rs:18, establish_pt_conn, proxy.rs:101); цикл `loop { select! }` в accept не ре-поллит завершённые futures; все-arms-disabled кейсов нет. `connection_permit` (lib.rs:651) — biased, cancel-safe форма.
- **§B3a**: accept-цикл классифицирует ошибки (fatal → return Err, fail-fast в `drive`), transient → bounded backoff с отменой; livelock-формы нет.
- **§F3 (async-сторона, клиент)**: абсолютные дедлайны на стадиях: SOCKS5-негоциация 10s (connection.rs:34), reply 10s (:80), upstream proxy 10s (proxy.rs:9/:107), obfs4 — бюджет покрывает dial+handshake (client.rs:519–527 `timeout_at(budget, async { stream_fut.await…; handshake })`), webtunnel — `deadline_for(timeout)` покрывает dial+upgrade (lib.rs:517–524). Ранние `?` не пропускают релиз регистраций: stdin-дубль под RAII (`StdinFd::drop`), permit освобождается drop'ом таска. Data-фаза без дедлайна — ингерентно туннелю, ограничена cap 1024 + teardown.
- **§B8**: брошенных lazy-future нет; `let _ = timeout(...)` в `reply_failure` (connection.rs:135) и `let _ = tx.send(true)` (server.rs:73) — оба с документированной best-effort семантикой (случай «receiver больше не ждёт» оговорён).
- **§B15e**: `interval()`/`Notify`/`watch` в крейте отсутствуют (проверено grep по b8982e3); select-циклы не пере-поллят завершённые futures.
- **§C3**: единый runtime tokio; async-std нет; WASM-целей нет.

## Что не проверено

- **Запуск/компиляция** — по условию `cargo` не запускался; всё — статический анализ. В частности, поведение `AsyncFd::register_with_interest` против safe `with_interest` на tokio 1.54.1 (мотивация GLMA-06) не воспроизводилось.
- **Тестовые файлы ветки** (`crates/lyrebird/src/client/socks_tests.rs` 229 строк, `unit_tests.rs` 157, `tests.rs`, `tests/proxy_error.rs`) — просмотрены по структуре только на предмет спавнов/таймингов; полный §D1-аудит оракулов не выполнялся (не входит в async-срез).
- **Wire-формат/крипто-конформность** obfs4/webtunnel (§F1/§B12), fcntl/AsyncFd-unsafe-семантика под Windows/WSL — вне async-среза.
- **`crates/core/src/helpers.rs::wait_stdin_close`** (spawn_blocking-вариант, doc `not cancel-safe` с обоснованием) — не изменён веткой, используется ли ещё кем-то кроме тестов — не прослежено.
- **`crates/ptrs-gesher` (busybox dispatch)** — только Cargo.toml менялся; не смотрел.

Итог: **P0: 0; P1: 1; P2: 2; P3: 4.**
