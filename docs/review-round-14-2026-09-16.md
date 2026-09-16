# Ревью ptrs-gesher — раунд 14

Дата: 2026-09-16. Проверенный диапазон последних принятых исправлений:
`bc54afd..7cd0e63` (7 коммитов, из них 6 кодовых). Текущий HEAD:
`7cd0e63cb3cb945abf2290dfa030b76219e88fd6`. Работа велась только в
выделенном worktree; исходный отчёт был единственным файлом агента. После
приёмки production-исправления перенесены в основной чекаут отдельно.

Метод: целевой ручной проход по исходникам с трассировкой фактических путей
вызова (не только по diff'ам). Объём — (A) проверка шести закрытых задач
PT13 в текущем коде; (B) общий просмотр obfs4 (handshake client/server,
sessions, framing/codecs, replay filter, IAT carrier/stream, state/builder),
lyrebird (managed-PT env, client/server setup, lifecycle/shutdown, logging
reload, stdin watch), core (трейты PT, helpers/env), webtunnel (точка входа
и конфигурация — обзорно), интеграция workspace. Это не полный аудит
криптопримитивов и не вывод о зависимостях по зелёным тестам.
`rust-intel` применён к cancel-safety/waker-контрактам (§B3, §B15b),
ресурсным границам (§F3), независимости оракулов (§D1a) и сверке с
задокументированными гарантиями (§F1–F2).

## Итог

Все шесть задач PT13-01…PT13-06 подтверждены закрытыми в текущем коде.
Новых дефектов в проверенном диапазоне исправлений не подтверждено.
В общем коде были подтверждены **один P2 и один P3**; оба существовали ранее
и теперь исправлены. P0/P1 в проверенном объёме не подтверждены.

| ID | P | Задача | Статус |
|---|---|---|---|
| PT14-05 | P2 | Не завершать listener после временной ошибки accept | Закрыта; retry с backoff |
| PT14-02 | P3 | Подставлять имена аргументов в ошибки server state | Закрыта; форматированное сообщение |

Первоначальные PT14-01, PT14-03 и PT14-04 исключены при приёмке;
основания приведены отдельно ниже. Нумерация сохранена для прослеживаемости.

Исправления: client accept loop различает известные transient и фатальные
ошибки; transient путь повторяется с ограниченным backoff и останавливается
по cancel. Server-state ошибки содержат конкретное имя отсутствующего поля.
Добавлен policy regression test.

## Scope A — проверка закрытых задач раунда 13

### PT13-01 — IAT применяется к фактической отправке carrier — ЗАКРЫТО

Механизм: `IatCarrier` (crates/obfs4/src/proto.rs:31-181). Для Enabled
каждая порция carrier ограничена `MAX_SEGMENT_LENGTH` (1448), для Paranoid
порция добивается паддингом до выбранной `length_dist` длины через
`pad_burst` (proto.rs:466-498) с точным учётом wire-заголовков. Задержка
ставится после завершения порции (proto.rs:148-161), частичная запись
продолжает ту же порцию без новой задержки. `poll_flush` проходит через
тот же планировщик (`poll_flush_with_iat`, proto.rs:528-554), в том числе
выжидает задержку последней порции перед flush нижележащего потока.
Shutdown отменяет задержки (`clear_delay`, proto.rs:70-73, 778-784), как
и заявлено в задачах. Трассировка waker'ов: каждое Pending из
`poll_ready_with_iat` / `poll_flush_with_iat` / `poll_close_with_iat`
гарантированно имеет зарегистрированный waker (таймер Sleep на
proto.rs:130-136/167-175, запись в сокет) либо установленный `pad_target`,
который обрабатывается в том же poll (см. исключённый PT14-01). Оракулы: скриптовый
carrier с записью размеров/моментов записей и частичной записью
(proto/tests.rs:11-102, 719-786), тест wire-длины паддинга с независимым
эталоном и аутентификацией всех кадров (proto/tests.rs:486-519),
отрицательные контроли для Off/Enabled/Paranoid. Ритмизация начинается с
первого кадра: Framed-буфер упирается в capacity через ~5 кадров, и
`poll_ready` вызывает flush; пачки, уходящей без IAT-задержек, больше нет.

### PT13-02 — числовой iat-mode Go statefile — ЗАКРЫТО

Механизм: `iat_mode_json` (crates/obfs4/src/lib.rs:26-144) — каноническая
запись числом `serialize_u8` 0/1/2; чтение принимает число и legacy-строку,
отклоняет 3, -1, 1.5, bool и float. Подключён к обоим состояниям:
`JsonServerState` (server.rs:456-469) и `JsonClientState` (client.rs:38-51).
Fixture-тест импортирует Go-формат с `"iat-mode": 2` (server.rs:781-794),
отрицательный тест server.rs:797-805. Каноническая запись теперь число —
совместимость со строками старых Rust-файлов сохранена.

### PT13-03 — общая effective configuration — ЗАКРЫТО

Механизм: `EffectiveServerConfiguration` с кэшем (server.rs:61-78, 280-364)
единый для `try_client_params` (server.rs:209-218) и `try_build`
(server.rs:237-278); релевантные setter'ы и `try_statefile_path` инвалидируют
кэш (server.rs:390-400). `ensure_statefile_unchanged` (server.rs:378-388)
сужает окно перезаписи внешних изменений, с честным комментарием о
не-CAS-остатке. Регрессионный тест строит сервер из statefile, публикует
параметры builder'ом и проводит реальный duplex-handshake этими параметрами
(server/tests/server_state_tests.rs:20-87); конфликт внешней замены файла
не затирает чужое состояние (server_state_tests.rs:122-150).

### PT13-04 — независимые keypair/node ID overrides — ЗАКРЫТО

Механизм: слияние в `resolve_effective_configuration` (server.rs:305-337):
`identity_override && !node_id_override` сохраняет node ID из statefile;
`!identity_override && node_id_override` берёт ключи из statefile с ID
builder'а; оба флага — полный ручной режим; ни одного — полное состояние.
Тесты: смена только пары ключей сохраняет ID, persists и проходит handshake
(server_state_tests.rs:177-223), оба порядка сеттеров (226-254), импорт
через `try_statefile_path` (257-274), путь PT `options()` без `node-id`
в аргументах (277-316).

### PT13-05 — перенастройка логирования в активных spans — ЗАКРЫТО

Механизм: `ManagedLayer` хранит metadata+значения полей каждого span
(logging_layer.rs:23-27, 190-236); thread-local `ACTIVE_SPANS`/`BOUND_FILTER`
(112-115); `sync_filter` при смене фильтра переигрывает активные на потоке
spans в НОВЫЙ фильтр (332-365), `enabled()` оценивает события новым
фильтром (152-166). Обновлённый subprocess-тест теперь требует ОТСУТСТВИЕ
DEBUG внутри старого span после reload на ERROR (logging_tests.rs:315-318)
и сохранение span-предикатов при ослаблении уровня (319-323) — прежняя
фиксация старого поведения убрана.

### PT13-06 — abort handles по task id — ЗАКРЫТО

Механизм: `HashMap<Id, AbortHandle>` (lifecycle.rs:170), вставка при spawn,
удаление по факту join через `try_join_next_with_id` (lifecycle.rs:236-265)
и в `join_connection_tasks` (284-300); владелец абортирует всё при drop
(194-210). Полный проход retain по всем хэндлам на каждое соединение убран.
Порядок блокировок connections→aborts в spawn и `try_lock` в `RunOwner::drop`
цикла не образуют. Память ограничена admission cap 1024.

## Подтверждённые находки

### PT14-02 — P3: сообщения о недостающих аргументах server state не интерполированы

Места: crates/obfs4/src/server.rs:501-502, 505-507, 510-512.

Триггер: `validate_args` / `RequiredServerState::try_from` с отсутствующим
`private-key` / `drbg-seed` / `node-id`.

Механизм: `.ok_or("missing argument {PRIVATE_KEY_ARG}")?` — литерал без
`format!`; пользователь видит дословно `missing argument {PRIVATE_KEY_ARG}`.
Клиентская сторона делает это корректно (crates/obfs4/src/client.rs:304,
307, 316).

Статус: исправлено форматированием имён аргументов; функциональный путь не
изменён.

Воспроизведение: `Args::new()` без полей → `validate_args` → ошибка с
литеральным `{PRIVATE_KEY_ARG}`.

Исправление: `format!("missing argument '{PRIVATE_KEY_ARG}'")` по образцу
client.rs. Существовало до диапазона (проверено в `bc54afd`).

### PT14-05 — P2: transient-ошибка accept навсегда завершает клиентский listener

Места: crates/lyrebird/src/lib.rs:628-635 (accept Err → `break`).

Триггер: любой `Err` от `listener.accept()` — в том числе transient
(EMFILE/ENOBUFS при пике соединений), а не только фатальные (EBADF).

Механизм: цикл не классифицирует ошибку; выход из цикла означает конец
listener-task, а при одном транспорте — `ExitKind::ProxyClosed` в `drive`
(lifecycle.rs:73-93) с drain'ом и завершением всего run с кодом успеха.
Ни retry/пауз, ни различения ошибок нет.

Статус: исправлено классификацией transient ошибок и повтором с backoff.

Влияние до исправления: после освобождения fd listener не возобновлял приём. При одном транспорте весь run завершался успешно; уже открытым соединениям давалось 15 секунд на завершение, затем оставшиеся отменялись. При нескольких listener терялся соответствующий транспорт.

Доказательство по коду: accept возвращает Err → break → Ok(()) из client_accept_loop → исчерпание JoinSet → ExitKind::ProxyClosed. Теперь известные resource/connection ошибки получают backoff и повтор. Искусственное исчерпание fd и сверка с эталонным obfs4proxy не запускались.

Исправление: `is_transient_accept_error` распознаёт системные resource и
connection ошибки, `accept_retry_delay` ограничивает backoff, а фатальная
ошибка возвращается владельцу. Существовало до диапазона.

## Исключённые пункты после приёмки

- **PT14-01, IAT waker:** `IatCarrier` — внутренний тип; все три текущих
  потребителя обрабатывают `pad_target` и повторяют poll в том же вызове
  (`proto.rs:504-582`). Зависание в текущем API не показано. Потенциальный
  будущий неправильный потребитель не считается текущим дефектом.
  Простой `wake_by_ref()` сам по себе не заменяет этот внутренний протокол.
- **PT14-03, повреждённый statefile:** `with_statefile_path` обещает загрузку
  существующего файла, а `try_build` — его валидацию (`client.rs:153-166`,
  `:220-244`). Разбор также защищает импортированный server state от записи
  клиентом. Ручные overrides не обещают игнорировать повреждённый файл;
  нарушение текущего контракта не подтверждено.
- **PT14-04, консольный stdin Windows:** ветка явно возвращает Unsupported,
  а lifecycle явно завершает работу при ошибке наблюдения
  (`stdin_watch.rs:343-352`, `lifecycle.rs:86-91`). Это ограничение поддержки
  консоли с `TOR_PT_EXIT_ON_STDIN_CLOSE=1`; managed pipe работает по другому
  пути. Замена ошибки на бесконечный pending отключила бы контроль родителя,
  поэтому исходная рекомендация не принята как исправление дефекта.

## Проверки, оракулы и ограничения

Команды и результаты (в worktree; CARGO_TARGET_DIR=../../target,
профильный debug выключен):

- `CARGO_TARGET_DIR=../../target CARGO_PROFILE_DEV_DEBUG=0
  CARGO_PROFILE_TEST_DEBUG=0 cargo test --locked -p ptrs-gesher-obfs4
  --lib -j1` → **221 passed; 0 failed**. ERROR-строки
  `invalid frame length after demask` в выводе — ожидаемый негативный шум
  proptest-контролей, не сбои.
- та же команда с `-p ptrs-gesher-lyrebird --lib -j1` → **45 passed;
  0 failed**.
- `cargo clippy --locked -p ptrs-gesher-obfs4 -p ptrs-gesher-lyrebird --all-targets -j 1 -- -D warnings` → passed.
- `cargo test --locked --workspace -j 1` → passed.
- Production diff затрагивает только `crates/lyrebird/src/lib.rs`,
  `crates/lyrebird/src/tests.rs` и `crates/obfs4/src/server.rs`; HEAD `7cd0e63`.

Что проверено чтением (без выполнения): waker/cancel-контракты IAT
(перечислены выше), lifecycle/shutdown-дерево lyrebird, порядок блокировок
`aborts`/`connections`, replay-фильтр (TTL ≥ 2ч закреплён тестом против
±1h epoch-окна; eviction/cap-семантика покрыта тестами), codecs
decode/decode_eof (TagMismatch/InvalidFrame фатальны, nonce не расходуется
зря при ошибке), константная арифметика pad_burst против FRAME/HEADER
констант.

Ограничения и непроверенные гипотезы (отдельно от находок):

- Полный workspace, examples, benches, CI-скрипты, webtunnel handshake/TLS
  и dns/ внутри, crate bridge-line, umbrella ptrs-gesher — в этом раунде
  НЕ рецензировались детально; webtunnel просмотрен на уровне точки входа
  и конфигурации.
- Go-interop (tools/interop/go) не запускался; реальный Tor-трафик и сеть
  по условиям задачи исключены. Соответствие Paranoid-длин кадрам эталона
  опирается на локальный тест-оракул proto/tests.rs:486-519; сверка с
  актуальным исходником Go в этом раунде не повторялась (в раунде 13
  выполнялась на закреплённом commit).
- Ускорение PT13-06 оценено из исходника; измерений не проводилось.
- Поведение эталонного obfs4proxy при transient accept-ошибках (PT14-05)
  не сверялось — влияние оценено по коду и механике accept-цикла.
- Зависимости не проверялись (audit/`cargo update` вне объёма); версии
  взяты из существующего Cargo.lock без изменений.

Замечания подтверждены анализом достижимых путей кода и policy regression
test; отдельный listener fault-injection fixture не запускался.
Зависимости, манифесты и lockfile не изменялись. Коммиты и push не выполнялись.
