# GLM-ревью API/Drop/зависимостей — 2026-11-05

Срез: HEAD `b8982e3fff90af3c0c76ccfabda0c7e8b04cec28` (ветка socks-carrier-160-20261104) + diff vs main. Методика: rust-intel lifetimes-and-api.md (§B1/§B1a/§B1b/§A3/§C1/§C1a/§C5/§C11) + drop-and-raii.md (§B4/§B4a) + deps-macros-ergonomics.md (§A1/§C6/§C7/§C10/§C12/§E5).

Read-only аудит: cargo не запускался, код не редактировался. Проверка `resocks5-net` выполнена по живому crates.io API (имя, checksum, издатель, даты публикаций) и docs.rs (семантика `Reply`); `tokio 1.53.3` — по crates.io. Network-проверки указаны явно, остальное — статика по `git show b8982e3:...`.

Шкала: P0 — критическая; P1 — высокая срочность; P2 — исправить в обычном цикле; P3 — ограниченное влияние. По SKILL.md Enforcement tiers: 🔴-обязательных к перечислению находок в этой ветке не обнаружено (§A1-деп проверен и верифицирован; blanket-impl в pub API нет; unsafe-изменение задокументировано с SAFETY).

## Сводка

| ID | P | Область | file:line | Находка |
|---|---|---|---|---|
| GLMD-01 | P2 | Логирование | crates/lyrebird/src/client/connection.rs:95 | Опечатка имени поля `addres` вместо `address` в `warn!` — записи о закрытии туннеля невидимы для фильтров по `address` |
| GLMD-02 | P3 | Структура модулей | crates/lyrebird/src/lib.rs:91-97 | Каталог `client/` не является модулем: файлы приклеены к корню крейта через `#[path]`, `connection.rs` тянет весь корень через `use super::*` |
| GLMD-03 | P3 | Релиз-инфра | Cargo.toml:18 | `workspace.metadata.release baseline-version = "0.7.0"` не поднят при подготовке 0.8.0 |
| GLMD-04 | P3 | Зависимости (cooldown) | crates/lyrebird/Cargo.toml:46 | `resocks5-net 0.4.1` опубликован 2026-11-02 — 3 дня до HEAD; в репо нет механизма cooldown (см. Зависимости) |
| GLMD-05 | P3 | §C10 дубликаты | Cargo.lock | `safelog 0.4.8` + `0.10.0` в одном бинаре (pre-existing, типы границу не пересекают) |
| GLMD-06 | P3 | Логирование | crates/lyrebird/src/logging_tests.rs:113-131 | Тест-цель `resocks5_net` в RUST_LOG-примерах использует имя деп-крейта как Magic Target без фиксации контракта |

Итого: **P0: 0; P1: 0; P2: 1; P3: 5**.

## Зависимости

Каждый новый dep ветки (vs main) с вердиктом:

| Dep | Версия (Cargo.toml → Cargo.lock) | Источник | Вердикт |
|---|---|---|---|
| `resocks5-net` | 0.4.1 → 0.4.1, `default-features = false` | crates.io (зеркало `registry+https://github.intra/...`) | **Принят.** См. разбор ниже |
| `url` | "2.5.8" → 2.5.8 | crates.io | Принят: уже был транзитивным в графе; новый прямой dep. Всемирно известный крейт (§C12-каталог сам его называет эталоном для URL) |
| `percent-encoding` | "2.3.2" → 2.3.2 | crates.io | Принят: транзитивен через `url` с 0.7; использование корректно (§E5 не нарушен — парсинг только на старте) |
| `base64` | "0.22" → 0.22.1 (dev-dep) | crates.io | Принят: уже prod-dep obfs4/webtunnel/resocks5-net; в lyrebird только тесты |
| `tokio` | "1.42" → "1.53.3"; lock 1.53.1 → 1.54.1 | crates.io | Принят: 1.53.3 существует (2026-10-13), 1.54.1 (2026-10-21) — RUSTSEC-2026-0386, документировано в CHANGELOG; floor 1.53.3 валиден |
| удалён `fast-socks5` | 0.10.0 → — | — | Удалён чисто: `git grep fast_socks5` пуст, включая бенчи/примеры/тесты; `PtArgsAuth` удалён; `tokio-stream` (его транзитивный) тоже вышел из lock |
| точечные апдейты lock | rustls-webpki 0.103.15→0.103.16, webpki-roots 1.0.9→1.0.11 | crates.io | RUSTSEC-мотивированные (CHANGELOG: RUSTSEC-2026-0381/0382), не blanket `cargo update` |

### Cargo.lock: resocks5-net (ручная правка — проверка)

Запись в lock корректна и согласована со всем остальным файлом:

```toml
[[package]]
name = "resocks5-net"
version = "0.4.1"
source = "registry+https://github.intra/rust-lang/crates.io-index"
checksum = "ccc654697444876723a347f724d1b9fd40619ff831975fdc760779bcceb4a840"
dependencies = ["base64", "socket2", "tokio"]
```

- **Checksum**: совпадает с контрольной суммой версии 0.4.1 на crates.io (проверено по API crates.io, 2026-11-05).
- **Источник**: registry (зеркало `github.intra`), **не** git и **не** path; тот же реестр, что у всех 483 записей lock (единственный `source =` в файле), и единственный разрешённый в `deny.toml` `[sources] allow-registry`. Ручная правка консистентна, orphan-записей после удаления fast-socks5 нет (`thiserror 1.0.69` остаётся с живым зависимым `postage 0.5.0`).
- **Кем опубликован**: первый-party крейт — репозиторий и издатель `PHPCraftdream` (тот же аккаунт, что у ptrs-gesher), trusted publishing с GitHub (run_id 41450708004, sha `b1b08bed…`). Не slopsquatting и не typosquat (§A1): имя принадлежит проектной организации. Нюанс: крейту 4 версии/1 месяц, загрузок 67 — фактически используется только этим проектом; независимого аудита байтов («review the published bytes») не проводилось — помечено в «Что не проверено».
- **`default-features = false`**: реально отсекает тяжёлые фичи — в графе только `base64, socket2, tokio` (без dashmap/rustls/serde/rotator из дефолтного набора `["pool","tls","serde","rating","rotator"]`). MSRV крейта 1.88 < workspace rust-version 1.92.
- **Cooldown (GLMD-04)**: 0.4.1 опубликован 2026-11-02, HEAD ветки — 2026-11-05. Механизма cooldown нет: `registry.global-min-publish-age` в конфиге не задан (и поддерживается только Cargo ≥ 1.100), Renovate/Dependabot в репо не настроены. Риск смягчён первым-party происхождением и `cargo-deny` в CI (`yanked = "deny"`, `unknown-registry = "deny"`). Рекомендация: после перехода CI на Cargo ≥ 1.100 включить `min-publish-age`, а для первого-party крейтов — сверять sha коммита trusted publishing с локальным main крейта.

### Границы workspace (§C10)

- resolver = "2" (корень), edition 2021 у всех членов — v1-ловушек с target-specific features нет.
- Новых semver-несовместимых дублей ветка не вносит. Pre-existing дубли: `thiserror 1.0.69`+`2.0.20` (оба с живыми зависимыми; 1.x тянется `postage` через tor-* стек), `safelog 0.4.8` (lyrebird) + `0.10.0` (tor-bytes/linkspec/llcrypto) — GLMD-05; значения через границу не ходят (lyrebird применяет `sensitive()` только к std-типам), цена — размер артефакта.
- Публикация: члены workspace имеют метаданные crates.io (docs.rs, categories) без `publish = false` — правила published-библиотек применимы к их pub-API; но см. «Находки»: новые модули прокси crate-private.

## Находки

### GLMD-01 — P2 — crates/lyrebird/src/client/connection.rs:95

```rust
warn!(
    addres = sensitive(client_addr).to_string(),
    "tunnel closed with error: {e:#?}"
);
```

**Механизм**: tracing-макрос принимает произвольные имена полей — компилируется без предупреждений. Поле пишется как `addres`, тогда как остальные два места в том же клиентском пути пишут `address` (crates/lyrebird/src/lib.rs:743, 867). Любой, кто фильтрует/алертит по полю `address` (или строит дашборд по структрированным логам), молча не увидит записи о закрытии туннеля с ошибкой — это единственное место, где логируется причина разрыва уже установленного туннеля.

**Сценарий**: мост обрывается по таймауту; дежурный ищет `address=…` в логах за окно жалобы пользователя — событие не находится, инцидент выглядит как «туннель пропал без записи».

**Фикс**: переименовать поле в `address` (опечатка переехала из старого lib.rs main-ветки, где была в той же логике — ветка переписала этот код и исправила соседнюю косметику, поле осталось).

### GLMD-02 — P3 — crates/lyrebird/src/lib.rs:91-97

```rust
#[path = "client/connection.rs"]
mod connection;
…
#[path = "client/proxy.rs"]
mod proxy;
```

**Механизм**: каталога-модуля `client/` не существует (нет `mod.rs`), три файла склеены в корень крейта через `#[path]`. Как следствие, `use super::*;` в connection.rs импортирует весь корень lib.rs (`sensitive`, `Result`, `warn!`, `TcpStream`, `SOCKS5_SETUP_TIMEOUT`, …) — видимость кода connection.rs неявно зависит от полного списка glob-импортов корня: удаление/переименование любого use в lib.rs молча меняет набор имён, доступных connection.rs. Аналогично подключены client/socks_tests.rs и (по прежнему паттерну) socks_tests.

**Сценарий**: рефакторинг импортов lib.rs ломает connection.rs только на непокрытой тестами ветке (например, добавят третий вариант ошибки, использующий имя, которое раньше приходило из glob).

**Фикс**: сделать настоящий модуль `mod client { pub(crate) mod connection; pub(crate) mod proxy; }` (или перенести файлы на уровень `src/`) и заменить `use super::*` на явные `use crate::{…}`. Поведение не меняется, зависимость от glob исчезает.

### GLMD-03 — P3 — Cargo.toml:18

```toml
[workspace.metadata.release]
baseline-version = "0.7.0"
```

**Механизм**: все шесть крейтов подняты до 0.8.0 (Cargo.toml, CHANGELOG, README, SECURITY), а baseline релиз-инструмента остался 0.7.0. Если `cargo release`/скрипты читают `baseline-version` (для diff-логов или проверки версий), следующий прогон будет считать 0.7.0 актуальной базой.

**Фикс**: поднять до `"0.8.0"` вместе с релизом либо подтвердить, что ключ не используется инструментами репо (тогда удалить).

### GLMD-04 — P3 — crates/lyrebird/Cargo.toml:46 (cooldown)

См. «Зависимости → Cooldown». Находка процесса, не кода: ручная правка lock в остальном образцовая (checksum+registry верифицированы), но свежесть 0.4.1 (3 дня) ничем не ограничена. Фикс: `registry.global-min-publish-age` в CI-конфиге после Cargo 1.100 и/или сверка sha trusted publishing с main первого-party крейта.

### GLMD-05 — P3 — Cargo.lock (§C10, pre-existing)

`safelog 0.4.8` (lyrebird) и `safelog 0.10.0` (tor-* стек) линкуются в один бинарь. Не введено веткой (есть и на main). Типы через границу дубликатов не передаются — только размер артефакта и время сборки. Ветка, убравшая fast-socks5, была удобным моментом и для консолидации safelog (лира использует из него только `sensitive`/`Guard`), но это отдельное решение. Зафиксировано как сигнал `deny.toml [bans] multiple-versions = "warn"`; повышать до deny — по готовности консолидировать.

### GLMD-06 — P3 — crates/lyrebird/src/logging_tests.rs:113-131

```rust
tracing::info!(target: "resocks5_net", "info-visible");
…
RustLogGuard::set(Some("error,resocks5_net=debug"))
```

**Механизм**: тесты фильтров завязаны на целевое имя зависимого крейта (`resocks5_net`) как на строковый литерал. Замена депа (уже случившаяся в этой ветке: `fast_socks5` → `resocks5_net`) требует правки тестов — контракт «какие деп-таргеты фигурируют в дефолтных фильтрах» нигде не зафиксирован, и при следующем переименовании депа тесты опять молча проверят устаревшее имя (они падают только там, где ожидается видимость).

**Фикс**: один `const DEP_LOG_TARGET: &str = "resocks5_net";` (или `concat!` из `env!("CARGO_PKG_NAME")`-подобного источника) в общем тест-модуле и использование его в обоих местах.

## §B4/§B22/§B4a — Drop-семантика: чисто

- `impl Drop` в новых файлах proxy.rs/connection.rs отсутствует. Существующие Drop-типы (LoggingGuard lib.rs:221, StdinFd stdin_watch.rs:45, EnvGuard core/helpers/test.rs:20, lifecycle RunOwner) — без паник/unwrap/lock-poison-распространения, async-работы в Drop нет (§B22: **факт — не обнаружено**).
- `process::exit`/`abort`/`mem::forget`/`ManuallyDrop`/`unsafe impl Send|Sync` — ноль вхождений по всему дереву `crates/` (grep).
- Drop-order дедлоков (join до закрытия Sender) нет: задачи владеет `JoinSet` (`RunTasks::spawn_connection` хранит abort-хэндлы и джойнит `try_join_next_with_id`; соединения завершаются по CancellationToken, а не по каналам).
- §B4a: edition 2021 по всему workspace (`[workspace.package] edition = "2021"`), миграции на 2024 нет; в диффе нет `if let` с guard'ами локов и RAII-темпорари в tail-позициях (все Mutex/RwLock-guard'ы в logging-коде связаны в `let` с явным `drop(state)`).
- Новый unsafe (stdin_watch.rs:75, `AsyncFd::register_with_interest` вместо RUSTSEC-2026-0386-поражённого `with_interest`) — вне секций задачи, но 🔴-класс §B5: SAFETY-контракт проверен — `StdinFd` владеет дублированным `OwnedFd` в течение всей жизни `async_fd`; `async_fd` объявлен после `watched` (локали), т.е. дропается раньше — дерегистрация из реактора предшествует закрытию дескриптора. CHANGELOG документирует мотив (RUSTSEC-2026-0386). Замечаний нет.

## §B1/§B1a/§B1b/§A3/§C1/§C1a/§C5/§C11/§C7/§E5/§C6 — чисто

- **§B1a/§B1b**: параметров `'a` в новых сигнатурах нет вовсе; кэшей, захватывающих заимствования, нет. Обратное улучшение: `resolve_target_addr` был `pub fn (&TargetAddr)` с чужим типом fast_socks5 в pub-сигнатуре опубликованного крейта — стал `pub fn (impl Display) -> Result<SocketAddr>`; breaking change задокументирован в CHANGELOG.
- **§A3/unnameable**: новые модули `proxy`/`connection` — **crate-private** (`mod`, не `pub mod`; элементы `pub(crate)`/`pub(super)`) — несмотря на физический путь `src/client/`, они не часть внешнего API, поэтому §C1a/`#[non_exhaustive]` на них не требуется. Новые pub fn опубликованных крейтов — `ptrs::ClientInfo::without_proxy()` и `webtunnel::WebTunnelClient::carrier_destination()` — возвращают nameable owned-типы `(String, u16)`/`ClientInfo`, документированы.
- **§C1 blanket impls**: нет (private-трейт `ManagedClient` с per-type impls; помечен «no public trait surface»). Для workspace-приватных крейтов 🔴-вопрос не стоит.
- **§C5**: рефлексивных `.clone()` нет — все клонирования обоснованы (per-connection `builder.clone()`/`proxy.clone()` для spawn, креды в `ProxyConfig`, `to_owned` таргета).
- **§C11**: `Deref`-имплов нет (`Prefixed` реализует AsyncRead/AsyncWrite напрямую — корректно).
- **§C7/§E5**: `build.rs` в репо нет вообще (проверено `git ls-tree -r`) — rerun-if-changed неприменим; `Regex` не используется; cfg-фичи (`experimental-server`, `debug`) консистентны между `[features]` и `#[cfg]`; unexpected_cfgs покрыт CI (`cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`). Proc-macros в ветке нет (§C6 не применим).
- **Мёртвый код**: старый `src/socks_tests.rs` удалён, его преемник `client/socks_tests.rs` подключён; `PtArgsAuth`, fast_socks5-хелперы и `tokio-stream` вычищены без остатка; каждая функция lib.rs (`dial_bridge`, `tune_outgoing`, `establish_pt_conn`, `is_transient_accept_error`, `accept_retry_delay`) имеет производственных или тестовых вызывающих.
- **Единообразие failure-путей** (проверка из задачи): connection.rs отправляет parent'у bounded best-effort failure-reply на обоих ошибках (`Reply::GeneralFailure`/REP 1 — невалидные PT-аргументы, `Reply::UpstreamUnavailable`/REP 4/HTTP 502 — транспорт/апстрим; семантика `Reply` сверена с docs.rs resocks5-net 0.4.1), ошибки value-free (`io::Error::other("upstream proxy connection failed")`, `anyhow!("invalid PT arguments")` без эха значений) — единообразно с недавней починкой; интеграционный тест `tests/proxy_error.rs` и юнит `invalid_pt_arguments_error_never_echoes_submitted_values` закрепляют недисплоужing секретов. README/CHANGELOG-заявления (REP-коды, PROXY DONE, IP-literal-only, no-fallback) сверены с кодом — расхождений нет.

## Что не проверено

- **Байты опубликованного `resocks5-net 0.4.1`** (содержимое .crate против его репозитория: build.rs/proc-macros/новые deps) — проверены только метаданные crates.io, checksum в lock и граф зависимостей lock. Для первого-party крейта этого достаточно при сверке sha trusted publishing; независимый аудит не проводился.
- **`experimental-server`-ветка** (server.rs) — вне диффа; shutdown-семантика серверного пути не ревьюилась (публично помечена как неполная).
- **`lifecycle.rs`/`logging_layer.rs`** — не в диффе; checked только `spawn_connection`/`RunOwner::drop` в точках, которых касается новый код.
- **Продолжительный прогон тестов/сборок** — запрещён правилами аудита (cargo не запускался); компиляционные проверки CI (clippy -D warnings, cargo-deny) предполагаются зелёными, но не верифицированы локально.
- **Windows-путь stdin_watch** (PeekNamedPipe/ReadFile) — только статическое чтение; поведенческие отличия pipe/console на реальной Windows-машине не воспроизводились.
- **Tor/arti-совместимость HTTP CONNECT на родительской стороне** — поведение parent'а (arti) с `CMETHOD socks5` при фактической двойной поддержке SOCKS5/HTTP на сокете не тестировалось против реального parent'а (интеграционные тесты используют синтетический peer).

Итог: **P0: 0; P1: 0; P2: 1; P3: 5**.
