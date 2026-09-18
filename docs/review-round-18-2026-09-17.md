# ptrs-gesher: повторное ревью исправлений и общего кода

> Статус при подготовке 0.6.0: PT18-01 закрыт коммитом `a605764`, PT18-02 —
> `8151427`. Ниже сохранён исходный отчёт для указанного в нём HEAD.

Дата: 2026-09-17. HEAD: `7e3b6b8cf33d3042465eda584a209600382e55d5`. Проверен диапазон `27e8e90..7e3b6b8`: env parser, listener-loss, durability и последний commit с echo-тестами. На старте tracked working tree чистое. `.target-local/` и `tools/interop/test.txt` не менялись. Предыдущий отчёт: [PT17](review-2026-09-17.md).

Шкала: P0 — критическая общая неисправность; P1 — высокая срочность; P2 — исправить в обычном цикле разработки; P3 — ограниченное влияние / устойчивость. **P0 — 0; P1 — 0; P2 — 1; P3 — 1.** Новые находки открыты.

## Сводка

| ID | P | Срез | Место | Проблема |
|---|---|---|---|---|
| PT18-01 | P2 | Общий тестовый код, затронутый `7e3b6b8` | `crates/obfs4/src/testing.rs:286–316` | Проверка получения 512 KiB находится в задаче, которую тест не join-ит |
| PT18-02 | P3 | Новый failure path durability | `crates/obfs4/src/lib.rs:178–187`, `server.rs:241–269` | После успешного persist и ошибки fsync повторный build использует устаревший observation |

### PT18-01 — P2: echo-тест может пройти без проверки принятого объёма

Место: [transfer_512k_x1](../crates/obfs4/src/testing.rs#L266), особенно reader task на строке 286 и возврат после flush на строке 316.

**Механизм.** `tokio::spawn` reader-задачи возвращает `JoinHandle`, который сразу теряется. Единственный `assert_eq!(received, expected_total)` находится внутри этой задачи. Основной тест ждёт только `write_all` и `flush` отправителя и возвращает `Ok(())`. Flush передачи не означает, что удалённая сторона вернула весь echo и reader успел его проверить. Runtime теста после возврата уничтожает оставшиеся задачи. Даже panic detached-reader не распространяется в результат теста.

**Влияние.** Зелёный `transfer_512k_x1` не подтверждает доставку 512 KiB в обе стороны. Замена 2-секундного guard на 30-секундный в последнем commit не исправляет оракул. Само отсутствие join существовало до commit; это остаточный дефект изменённого теста, а не регрессия от увеличения timeout.

**Дополнительный путь.** Reader добавляет `0` при EOF и продолжает `while received < expected_total`; sleep создаётся заново на каждой итерации. После добавления join также нужно обрабатывать преждевременный EOF, иначе тест может зациклиться вместо содержательного отказа.

**Исправление.** Сохранить и дождаться reader handle, пробросить его panic/error, проверить длину и содержимое в наблюдаемом результате; остановить и join-ить echo task. Deadline должен ограничивать всю наблюдаемую передачу, EOF до полного объёма — немедленная ошибка. Mutation-проверка: отбросить часть echo и убедиться, что внешний test result меняется на failure. В этом проходе mutation не выполнялась; доказательство — ownership и control flow теста.

### PT18-02 — P3: directory-fsync failure оставляет builder в невосстанавливаемом cached состоянии

Места: [persist → fsync](../crates/obfs4/src/lib.rs#L178), [try_build](../crates/obfs4/src/server.rs#L241), [effective cache](../crates/obfs4/src/server.rs#L280), [observation comparison](../crates/obfs4/src/server.rs#L378).

**Механизм.** Новый `sync_parent_directory(parent)?` выполняется после успешного `persist(path)`. При его ошибке конечный файл уже заменён. `try_build` выходит через `?` из `server.write_statefile_to`, до обновления effective cache. Кэш продолжает хранить прежний `StatefileObservation.contents` и `persist_statefile=true`.

**Контрпример.** Первое создание server state: observation равен `None`. Persist записывает JSON, fsync каталога возвращает ошибку. После устранения причины повторный `try_build()` на том же builder берёт cached effective config; `ensure_statefile_unchanged` сравнивает уже записанный JSON с `None` и отказывает как при внешней замене. Для override существующего state аналогично сравнивается старое содержимое с новым. Комментарий «a retry reloads the already-persisted file» не соответствует этому cached пути.

**Влияние.** Временная ошибка durability требует пересоздать/явно переинициализировать builder вместо успешного retry. Утрата identity или повреждение JSON этим сценарием не утверждаются. Unix error path проверен чтением; физический сбой диска и fault-injection не выполнялись, поэтому P3.

**Исправление.** Различать отказ до публикации и отказ подтверждения durability после неё; обновлять собственный observation либо безопасно инвалидировать effective cache, сохраняя согласованность уже вычисленных client params и ручных overrides. Regression должен один раз отказать на dir-fsync после успешного persist и затем проверить повторный build того же builder и неизменность identity.

## Что исправлено по предыдущему ревью

| Пункт | Результат |
|---|---|
| Пустой `TOR_PT_EXTENDED_SERVER_PORT` | Parser корректно трактует как отсутствие; ветка непустого адреса сохранена |
| PT17-01: fatal listener → success | Закрыт: `ListenerFailed(cause)` сохраняет причину, cleanup завершается до возврата Err; предусмотрен отказ одного из нескольких listeners и panic |
| PT17-02: отсутствие dir-fsync | Исходный пробел на Unix закрыт, пустой parent нормализован; новый post-persist retry defect выделен PT18-02 |
| Commit с echo timeout | Остановка чтения после достижения total исправляет лишнее ожидание; общий guard расширен. Проверка `transfer_512k_x1` всё ещё не наблюдается вызывающим тестом |

## Проверки и общий охват

Выполнено:

```text
CARGO_PROFILE_TEST_DEBUG=0 cargo test --locked -p ptrs-gesher-lyrebird --lib listener_ -j 1
3 passed; 0 failed; 46 filtered out
```

Фильтр выполнил fatal-error, panic-propagation и client listener setup тесты. Он не является полным lifecycle suite. PT18-01/02 подтверждены чтением исходников и error paths, отдельные воспроизводящие тесты для них не запускались.

Повторно просмотрены core env setup, managed client startup, listener/connection shutdown, state builder и atomic persistence, error handling изменённых тестов. Общий проход дополнительно затронул WebTunnel TLS/HTTP-upgrade/header-boundary, DNS modes, obfs4 framing decode/buffer paths и logging span replay. Неизменённые участки сверены с предыдущим обзором. Это ограниченный ручной проход по направлениям rust-intel, без субагентов, не полный аудит криптопримитивов, всех framing-комбинаций, unsafe/FFI, semver/CVE или всех платформ.

Существующий экспериментальный server режим по-прежнему явно незавершён и выключен по умолчанию; он не объявлен новым дефектом клиентского режима. Windows directory-entry durability остаётся явно указанным ограничением, а не ошибкой только что добавленной Unix-ветки. Полные workspace tests/clippy из прошлых ходов не приписываются этому запуску. Production, версии и зависимости не менялись; commit/push не выполнялись.
