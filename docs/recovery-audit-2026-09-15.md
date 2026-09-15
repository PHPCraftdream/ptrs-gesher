# Восстановление исправлений по истории сессии

> Историческая инвентаризация ниже описывает состояние до исправлений.
> [Результаты нового прохода](#результаты-нового-прохода) приведены в конце.

Дата: 2026-09-15. Проверен текущий HEAD `ead69a35829e1113f4f72ec3928ccab95a0ec214`.
Источник старого состояния — сохранившиеся сообщения, diff и результаты ревью
в рабочей сессии 7–11 сентября. Старые Git-объекты не используются как источник:
`921452f` и `aadbe48` отсутствуют в нынешнем clone.

Это инвентаризация и план, не запуск нового цикла разработки. Production-код,
тесты, версии, Git-история не изменены. Новые тестовые прогоны не выполнялись.
Ниже — подтверждённый минимум по доступной истории, а не дословная копия всех
утраченных отчётов и не гарантия полноты восстановления.

## Опорные факты из сессии

- `aadbe48`: исправления конфигурации, жизненного цикла и прочие результаты
  подготовки релиза; `612ad6d`: подготовка 0.6.0; `ac146bb`: отчёты до раунда 10.
- `921452f`: четыре исправления PT11 были перенесены в main. Тогда независимо
  прошли 394 Windows-теста затронутых крейтов, clippy и fmt.
- В PT10 были исправлены форматы аргументов, взаимодействие с чужим log-логгером,
  лишняя случайность при преобразовании seed, наследование cancel pipe,
  грамматика имён PT и roundtrip транспорта с именем Bridge.
- Ручное ревью 11 сентября подтвердило PT11 на Windows и нашло PT12-01/02.
  Эти две находки ещё НЕ были исправлены. Linux-приёмка PT11 не была завершена.
- Прежняя автоматическая оркестрация остановлена пользователем. Она не возобновляется.

## Повторить исправления, адаптируя к нынешнему коду

P0/P1 по этой сверке не подтверждены. P2 — функциональный дефект при конкретных
условиях; P3 — менее существенный дефект. Очередь восстановления указана отдельно
от P-классификации; связанные дефекты сгруппированы.

| Приоритет | Очередь | Пакет | Что восстановить | Что сейчас подтверждено |
|---|---|---|---|---|
| P2 | 1 | R01: WebTunnel carrier | Контракт wrap/establish, отдельное подключение по URL | `wrap` уничтожает io, `establish` уничтожает input; оба напрямую подключаются по config |
| P2 | 1 | R02: obfs4 write/error | Учёт уже принятого префикса, корректные ошибки и terminal shutdown | После start_send и роста len_sent последующий poll_ready может вернуть Err; FrameError хранит I/O как String |
| P2 | 1 | R03: Lyrebird abort | Owner drop-guards для отмены accept/connections при abort самого run | RunTasks создаётся без owner guards; orderly shutdown работает только при завершении future |
| P2 | 2 | R04: аргументы | Раздельные SOCKS и SMETHOD parse/encode | Один parser считает разделителями и запятую, и точку с запятой |
| P2 | 2 | R05: obfs4 public configuration | Реальные from_params/get_args/Display; честные ошибки неподдерживаемого | from_params/from_statefile возвращают пустую конфигурацию; get_args пуст; as_opts/Display пусты; set_args возвращает Ok без изменения |
| P2 | 2 | R06: server identity/state | Проверка согласованности ключей и использование заданного seed | node_keys игнорирует переданную public половину; options оставляет применение drbg_seed в TODO; session генерирует новый seed |
| P2 | 2 | R07: bind/state setters | WebTunnel bind по семейству адреса; явные ошибки unsupported там, где функция отсутствует | v4/v6 WebTunnel и setters obfs4 возвращают Ok, игнорируя параметры |
| P2 | 2 | R08: timeout overflow | PT11-03: checked_add и InvalidInput до dial/session | MaybeTimeout::deadline снова использует Instant + Duration |
| P2 | 2 | R09: owned logging | Перенастройка своего файла/уровня, disable, re-enable; точное владение dispatcher | Первый subscriber сохраняется, но последующие вызовы сразу возвращают Ok и не меняют свой файл/уровень |
| P3 | 3 | R10a: PT-имена | Проверка грамматики имени транспорта | Имена допускают дефис и цифру в начале |
| P3 | 3 | R10b: транспорт Bridge | Сохранение транспорта при parse → Display → parse | Display не добавляет префикс для транспорта Bridge |
| P3 | 3 | R11: Seed conversions | PT10-03: копирование готового seed без обращения к RNG | TryFrom<&[u8]> снова вызывает Seed::new до проверки длины |
| Проверки/выпуск | 3 | R12: проверки и выпуск | Утраченные доказательства, interop и безопасный release pipeline | Нет прежних interop/release-check скриптов и большинства специализированных regression tests |

R12 — этап восстановления проверок и выпуска, а не отдельный runtime-дефект;
самостоятельный P-приоритет ему здесь не присваивается. Начать следует с R01–R03.

### R01 — не потерять новый DNS/TLS cache при возврате контракта

Место: [WebTunnel transport](../crates/webtunnel/src/lib.rs#L435).
Ранее исправлялись PT4-01 и PT5-01: переданный stream/dial — реальный carrier.
Нельзя молча обходить маршрут embedding-приложения, прокси или bound socket.
Подключение по `url=` должно быть отдельным явным API, а managed-PT вызов
нужно адаптировать к нему, чтобы косметический bridge.addr не стал целью dial.

Сохранить нынешние общие resolver/TLS caches и бюджеты DNS fallback.
Возвращая establish, одновременно вернуть PT11-04: MissingUrl до первого poll
переданного dial. Сейчас MissingUrl возвращается рано, но только потому, что
сам dial вообще выбрасывается — полного правильного контракта это не обеспечивает.

Проверки: только переданный duplex/socket несёт TLS/Upgrade/payload;
ошибка dial наблюдаема; прямой резервный dial не происходит; pending dial
ограничен общим бюджетом; отдельный URL-connect работает.

### R02 — переносить поведение AsyncWrite, сохраняя новую borrowed encoding

Места: [poll_write](../crates/obfs4/src/proto.rs#L308),
[flush/shutdown](../crates/obfs4/src/proto.rs#L426),
[конверсия I/O error](../crates/obfs4/src/framing/mod.rs#L199).
В сессии закрывались дефекты частичного принятия, повторной отправки после
Interrupted, ошибок shutdown и сохранения ErrorKind.

Сейчас start_send принимает первые кадры, после чего следующий poll_ready
может вернуть Err вместо Ok(len_sent). Ошибка сообщает вызывающему неверный
результат записи; повтор может дублировать уже принятый префикс.
Отдельно I/O -> FrameError::IO(String) -> io::Error::other теряет kind.
Прямой poll_close снова не содержит прежнего явного состояния terminal error.
Точные случаи shutdown нужно воспроизвести, а не объявлять все новые изменения
ошибочными по отсутствию старой структуры файлов.

Проверки: IAT Off/Enabled/Paranoid, ошибка до первой записи и после префикса,
частичная отправка, flush/shutdown, повтор после Interrupted, отсутствие
дублирования и сохранение kind. Прежние borrowed payload, scratch и AEAD reuse
не откатывать — новые доработки уже реализуют их заново.

### R03 и R09 — новая библиотечная точка входа полезна, но не заменяет всё

Места: [run_managed](../crates/lyrebird/src/lib.rs#L331),
[RunTasks](../crates/lyrebird/src/lifecycle.rs#L162),
[logging init](../crates/lyrebird/src/lib.rs#L134).

`run_from_env()` теперь позволяет embedding без clap и чужой настройки логов.
Сохранить этот API. Старый RunOptions не следует автоматически возвращать
как breaking replacement нынешнего run().

Нужно вернуть owner guards в frame владельца run, не в разделяемую копию ctx:
на внешнем abort должны сработать токены accept/connections. Отдельно проверить
освобождение сокетов и permit после отмены; штатное join не доказывает abort-путь.

Для логов сохранить нынешнее уважение к subscriber приложения, RUST_LOG и
срок жизни safelog guard. Если библиотека владеет своим subscriber, повторный
запуск должен уметь выключить файл, сменить destination/level и включить обратно.
Проверять tracing и log на тех же callsite, включая неудачную перенастройку.
В истории отдельно устранялось влияние reload на чужой log::max_level:
этот отрицательный контроль нужен при возврате динамической настройки.

### R04–R08 и R10–R11 — локальные возвраты

- SOCKS использует `;`, SMETHOD использует `,`; другой знак остаётся частью
  значения. Вернуть явные парные API и тесты escaping/roundtrip, сохранив
  новую экономию аллокаций. Пример SOCKS: `url=https://example/x?a=1,2`.
- from_params должен применять cert/iat; get_args — валидировать и изменять
  конфигурацию транзакционно; as_opts/Display — возвращать параметры.
  from_statefile/set_args не должны сообщать успех отсутствующей реализации.
- Проверять supplied private/public pair до изменения builder; configured
  server seed должен доходить до session и соответствующих распределений.
  В сессии это проверялось реальным чтением statefile и отрицательной мутацией.
- WebTunnel v4/v6 bind хранить и применять к соответствующему dial-семейству.
  Для unsupported setters других транспортов сообщать ошибку, не Ok.
- Duration::MAX: checked_add -> InvalidInput на client wrap/establish и
  server wrap до I/O; обычные Fixed/Length/Default/fail_fast сохранить.
- PT-name: `[A-Za-z_][A-Za-z0-9_]*`. Для транспорта `Bridge` Display должен
  позволять восстановить именно транспорт, а не спутать его с директивой.
- Готовый seed конвертировать детерминированно: длина, копирование; RNG нужен
  только при генерации нового seed.

## Уже восстановлено иначе — не откатывать

Подтверждено чтением текущего кода и новых diff, без нового тестового прогона:

- `83b0df3`: stdin future принадлежит run; EOF наблюдается и при graceful drain;
  завершённый shutdown собирает connection tasks; ошибки TOR_PT_PROXY редактируются.
- Новый `lyrebird/src/stdin_watch.rs`: Unix AsyncFd и duplicate с CLOEXEC,
  повтор Interrupted; Windows обрабатывает результат ReadFile, EOF и ошибки.
  Поэтому PT10-04 и PT11-01/02 нельзя механически восстанавливать старым
  core::StdinWatcher с отдельным потоком. Нужны эквивалентные тесты нового пути.
- `ead69a3`: replay filter при out-of-order timestamps/capacity, SOCKS setup
  timeout, lazy DNS/TLS caches, per-address/fallback budgets, borrowed encoding,
  reusable buffers, линейное построение alias tables, меньше RNG/parse allocations.
- `run_from_env()` и сохранение host subscriber/safelog policy.
- Обычные absolute/relative deadlines obfs4, ранее опубликованные исправления
  padding/EOF/handshake over-read и WebTunnel URL/IPv6 уже есть в базе/новых правках.
- `4bfa56e`: обновление rustls. Возврат старого Cargo.lock уничтожил бы это обновление.

## PT12: не потерянные исправления, а прежние незакрытые задачи

1. PT12-01 (P2): `http://127.0.0.1:80` теряет explicit default port при
   нормализации Url; `validate_proxy_url` использует port().is_none и отвергает
   строку. Учитывать исходную authority и нормализованное числовое значение.
2. PT12-02 (P2): setters statefile_path принимают путь, но build его игнорирует.
   Это отдельный контракт от server options/parse_state. Восстановление R05/R06
   само по себе не закрывает обещание сохранения состояния через эти setters.

Обе задачи были записаны 11 сентября, но готового исправления в сессии не было.

## R12: восстановить доказательства и подготовку релиза отдельно

Утраченные целевые наборы: конфигурация obfs4, supplied-carrier WebTunnel,
deadline overflow, I/O roundtrip/errors, IAT retry/shutdown, logging reconfigure,
грамматика/roundtrip PT names. Для нового watcher перенести условия тестов,
а не их зависимость от старого типа StdinWatcher.

В сессии также были Go obfs4 interoperability во всех IAT-режимах и проверка
ошибочного ответа; защита lifecycle-тестов от Linux self-connect; MSRV,
feature matrix, release checks и packaging. Старые положительные результаты
не являются результатами для ead69a3 — проверки нужно провести после возврата.

Подготовка 0.6.0 включала migration/releasing docs, package metadata/licenses,
проверяющие release/publish скрипты и Trusted Publishing. Нынешнее состояние
по-прежнему 0.5.3 и с token-based publish.sh. Восстанавливать release tooling
нужно отдельным этапом после поведения; не менять версии/lockfile автоматически.
Публикация и настройка аккаунтов этим документом не разрешаются.

## Рекомендуемый порядок

1. Сохранить нынешнее состояние как основу восстановления.
2. R01–R03: carrier, write/error, отмена owner.
3. R04–R09: конфигурация, seed/identity, bind, overflow, logging.
4. R10–R11 и две прежние PT12-задачи.
5. Восстановить регрессионные тесты, выполнить Windows/Linux и interop приёмку.
6. Затем сверить публичный API и release tooling; выпуск выбрать отдельно.

Этот список можно использовать как вход для отдельных задач. Автоматические
исполнители не запускаются; завершёнными пункты здесь не объявляются.

## Результаты нового прохода

По отдельному поручению пользователя исправления реализованы поверх `63826aa`
семью агентами `hl` в отдельных worktree. Изменения проверены при интеграции;
обнаруженные ошибки реализации и тестов исправлены в этом же проходе.
Все созданные worktree удалены. Версии, теги и опубликованные пакеты не менялись;
коммитов и push в рамках этого поручения не выполнялось.

| Пункты | Результат |
|---|---|
| R01 | `wrap`/`establish` используют supplied carrier; managed WebTunnel вызывает `connect_url`. Проверены TLS ClientHello, Upgrade, payload, dial error, timeout и отсутствие poll при ошибке конфигурации. |
| R02 | Принятый префикс возвращается до отложенной ошибки; сохраняются ErrorKind и OS code. Проверены все IAT-режимы, частичная запись, Interrupted, отсутствие дублирования, terminal flush/shutdown и запись после shutdown. Borrowed payload и scratch reuse сохранены. |
| R03 | Владелец run отменяет accept/connections; отдельные abort handles закрывают гонку регистрации при отмене. Проверены занятый scheduler lock, освобождение permit и EOF сокета. |
| R04 | SOCKS и SMETHOD имеют отдельные parse/encode API. Примеры, property tests и SOCKS-вызовы Lyrebird переведены на соответствующий формат. |
| R05 | Реализованы параметры клиента, Display, state import и транзакционный `try_get_args`. Старый `get_args` сохраняет сигнатуру и откладывает ошибку до handshake. Добавлены `try_build`; неподдерживаемые legacy API сообщают ошибку. |
| R06 | Проверяются private/public пары. Заданный length seed передаётся сессиям; IAT seed выводится через SHA-256. Ошибка RNG не подменяется нулевым seed. |
| R07 | WebTunnel применяет bind по семейству адреса при URL dial и отклоняет bind для supplied carrier. Unsupported bind obfs4 и persistent state WebTunnel возвращают ошибки. |
| R08 | Deadline создаётся через checked_add; Duration::MAX отклоняется до dial/session. Fixed/Length/Default/fail_fast сохранены. |
| R09 | Собственный dispatcher определяется по точному владению. Перенастраиваются файл и фильтр, включая известные callsite и активные spans; foreign logger/subscriber и log max level сохраняются. Проверены failed reopen, disable/re-enable, смена destination и field directives. |
| R10–R11 | Исправлены грамматика PT-name, roundtrip транспорта Bridge и преобразование готового seed без RNG. |
| PT12-01 | Явный default proxy port распознаётся по исходному authority; отсутствующий/пустой порт отклоняется. Есть IPv4, IPv6 и userinfo проверки. |
| PT12-02 | State setters действительно загружают/сохраняют состояние. Ручные поля объединяются с состоянием по отдельности. Клиентский файл отделён от серверского; импорт серверского файла не переписывает приватную идентичность. Запись использует уникальный tempfile и atomic replacement, Unix mode 0600. |
| R12 | Добавлены конечный Rust/Go interop runner и локальные release gates; примечания по API собраны в [VALIDATION.md](VALIDATION.md). В feature matrix обнаружена и исправлена отсутствующая `required-features` у примера umbrella. |

Подтверждённые проверки этого прохода:

- Windows: workspace tests со всеми features; после последних изменений повторно
  проверены Lyrebird и затронутые WebTunnel тесты; clippy всех targets/features
  с `-D warnings`, rustdoc с `-D warnings`, doctests и fmt.
- Linux: workspace tests со всеми features в debug и release. Единственное
  начальное падение logging subprocess из-за наследованного `RUST_LOG=off`
  исправлено; повторный Lyrebird и полный release-набор прошли. Проверки нового
  stdin watcher и защиты от TCP self-connect сохранены.
  После финальных изменений повторно прошёл release-набор библиотечных тестов.
- Rust/Go obfs4: IAT 0/1/2 в обоих направлениях, по 4 KiB request/reply,
  проверка malformed reply и завершения обоих процессов — Windows и Linux.
  Linux Go helper предварительно собран установленным Go с GOOS=linux;
  runner явно сообщает пропуск своей стадии Go build.
- MSRV Rust 1.89: workspace со всеми features; отдельные сборки каждой feature
  и каждого пакета без default features.
- `cargo-semver-checks`: все шесть библиотек относительно `63826aa` прошли;
  несовместимость публичного API проверкой не обнаружена. Изменённые поведенческие
  контракты документированы отдельно.
- `cargo deny check`: advisories, bans, licenses и sources прошли.
- `cargo package --workspace --exclude ptrs-gesher-examples --locked --allow-dirty`:
  все шесть архивов созданы и проверены сборкой, включая зависимости между ними.
- Лимит 1000 строк соблюдён; owner/cancellation tests вынесены в
  `crates/lyrebird/src/lifecycle_tests.rs` и ограничены временем ожидания.

Проверки выполнены локально. Внешний CI этого незакоммиченного состояния не
запускался. Выбор версии и способа следующего выпуска остаётся отдельным действием;
trusted publishing и registry credentials не перенастраивались.
