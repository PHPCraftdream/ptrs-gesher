# GLM-ревью тестов и семантики — 2026-11-05

Срез: HEAD `b8982e3` (ветка `socks-carrier-160-20261104`) + diff vs `main` (`b2f793c`). Методика: rust-intel `testing.md` (§D1, §D1a, §D2–§D5, §E6) + `semantics-and-conformance.md` (§F1–§F4) + SKILL.md «Tier F — how to review for meaning» (fetch-референс, контрфактическое рассуждение, enumerate-don't-sample).

Объём diff: `crates/lyrebird/src/client/{proxy.rs, connection.rs, socks_tests.rs}` (новые), `src/unit_tests.rs` (новый), `src/tests.rs` (переработан), `tests/proxy_error.rs`, `src/lib.rs` (переработан), `crates/core/src/helpers.rs` (+`without_proxy`). Код handshakes к upstream-прокси вынесен во внешний crate `resocks5-net 0.4.1` (crates.io).

Правила соблюдены: `cargo` не запускался, код не редактировался. Все тесты ниже — проект, не реализация. Внешние референсы (spec.torproject.org, исходники obfs4proxy, crates.io-исходник resocks5-net) в офлайн-среде недоступны — соответствующие пункты помечены явно.

## Сводка

| ID | P | Область | file:line (b8982e3) | Находка |
|---|---|---|---|---|
| GLMT-01 | P1 | PT-spec §3.1 | lyrebird/src/lib.rs:588,599 | `VERSION-ERROR no-version` никогда не эмитится; при несовпадении `TOR_PT_MANAGED_TRANSPORT_VER` PT печатает `VERSION 1` и умирает молча |
| GLMT-02 | P1 | PT-spec §3.2.1 | lyrebird/src/lib.rs:552 | `ENV-ERROR` никогда не эмитится; ошибочные env (оба/ни один TRANSPORTS) → тихий exit без строки на control channel |
| GLMT-03 | P2 | HTTP CONNECT / SOCKS5 client (§F1, §D1a) | lyrebird/src/client/proxy.rs:130–150 | Конformance handshake делегирована resocks5-net; тесты гоняют client против server **того же crate** — самосогласованная пара, внешний RFC-оракул отсутствует; статусы 2xx-range, case-insensitivity заголовков, chunked — не проверены (reference unavailable) |
| GLMT-04 | P2 | §F3 upstream deadline | lyrebird/src/client/proxy.rs:9,107 | Whole-operation `CONNECT_TIMEOUT` (10s) не покрыт ни одним тестом; guarantee «один дедлайн на весь handshake, без per-stage reset» не закреплена |
| GLMT-05 | P2 | upstream stage failures | lyrebird/src/client/proxy.rs (tests) | Не покрыты стадии: upstream закрылся после method-selection reply; посреди auth; auth-статус ≠ 0; после auth до CONNECT reply (закрытие до greet — покрыто) |
| GLMT-06 | P2 | RFC 1928 ATYP | src/tests.rs:237–246, socks_tests.rs | Parent-side ATYP=3 (domain → REP=4, без DNS) и ATYP=4 (IPv6 target) не покрыты e2e; REP=8 (ATYP not supported) не эмитится никогда — без `// DEVIATION` |
| GLMT-07 | P2 | RFC 1929 границы | unit_tests.rs:30–45, proxy.rs:103 | 255-байтовый domain в `connect()` (верхняя граница) и end-to-end concat-форма >255 байт не покрыты; есть только unit-уровень |
| GLMT-08 | P2 | §D1a fragmentation | socks_tests.rs, proxy.rs (tests) | Все handshake-пиринги пишут reply целиком одним `write_all`; adversarial chunking (по 1 байту) для upstream-клиентского пути отсутствует |
| GLMT-09 | P2 | HTTP CONNECT без creds | connection.rs:53–56 | Путь `Protocol::Http` + `creds == None` (CONNECT без Proxy-Authorization → пустые args → default builder) не покрыт end-to-end |
| GLMT-10 | P2 | PT-spec §3.3.3 | весь diff | `TOR_PT_OUTBOUND_BIND_ADDRESS_V4/V6` не реализованы нигде; нет `// DEVIATION`/документации об отклонении |
| GLMT-11 | P2 | RFC 1928 REP-коды | connection.rs:62,74 | Эмитится только подмножество {0,1,4}; REP=2/3/5/6/7/8 никогда; «network unreachable» (REP=3) мапится в 4 — отклонение от §6 без комментария |
| GLMT-12 | P3 | Proxy::parse границы | proxy.rs:39–79 | Не покрыты: query (`?x=`), fragment (`#`), IPv6 zone-id (`%25eth0`), двойной `@` в userinfo, `socks5://` без authority, `http://` без порта |
| GLMT-13 | P3 | connect() guard-arms | proxy.rs:103 | `port == 0` и `host.len() == 256` на уровне `connect()` не протестированы (только через parse); мёртвая ветка `Https` не закреплена |
| GLMT-14 | P3 | Prefixed reader | socks_tests.rs:186–209 | Пустой prefix и побайтовая доставка prefix через poll_read не покрыты |
| GLMT-15 | P3 | http_credentials амбiguity | connection.rs:104–111 | Аргументы, честно заканчивающиеся на `:`, теряют символ (marker-коллизия) — поведение не задокументировано тестом |
| GLMT-16 | P3 | from_env портативность | proxy.rs:19–27, tests/proxy_error.rs:165 | Non-UTF8 `TOR_PT_PROXY` e2e-тест только `cfg(unix)`; на Windows путь не покрыт (unit-тест на `from_env` был бы портативен) |
| GLMT-17 | P3 | §D1 слабый оракул | src/tests.rs:319–320 | `let _ = timeout(5s, handler).await;` — результат handler'а отброшен в `client_handle_connection_tunnels_…` (не load-bearing, но assertion доступен и потерян) |
| GLMT-18 | P3 | §D3 CI | .github/workflows/ci.yml | Нет `cargo test --release` job: obfs4 делает арифметику на недоверенных значениях (framing length mask, probdist debug_assert tripwire) — debug-профиль не является свидетельством о release |
| GLMT-19 | P3 | §D1 wall-clock (вне diff) | obfs4/tests/e2e_security.rs:64–75 | Захват hello с `Instant::now()` бюджетом 500ms + `sleep(200ms)` синхронизация — претендент на flake; pre-existing, не тронут diff'ом |

Итого: **P0: 0; P1: 2; P2: 9; P3: 8**.

## Соответствие спецификациям

### SOCKS5 (RFC 1928/1929) — parent-facing server

Обязательные состояния/коды, выписанные из RFC до чтения кода (enumerate, don't sample):

| Случай из RFC | Код/тест |
|---|---|
| VER=5 greeting, parse версии | ✓ (resocks5_net); мусорная версия (VER=4) не протестирована → GLMT-12-родственный gap |
| Метод 0x00 NO_AUTH | ✓ `sdk_parent_negotiation_preserves_anonymous_mode` ([5,0] pinned) |
| Метод 0x02 USERPASS | ✓ `sdk_parent_negotiation_prefers_password_for_pt_arguments` + `socks5_client_connect` |
| 0xFF NO_ACCEPTABLE reply | ✗ нет теста (parent предлагает только GSSAPI 0x01 → ожидать [5,FF]) |
| RFC 1929 subneg VER=1, статус [1,0] | ✓ pinned (`reply == [0x01, 0x00]`) |
| CONNECT REP=0 Established | ✓ pinned байт-в-байт `[05 00 00 01 00…00]` (BND zeros — контракт) |
| REP=1 GeneralFailure | ✓ `invalid_pt_arguments_get_failure_reply_without_dialing` |
| REP=4 UpstreamUnavailable | ✓ `client_handle_connection_no_success_reply_when_bridge_not_obfs4`, `unreachable_upstream_proxy…` |
| REP=2/3/5/6/7/8 | ✗ не эмитятся никогда — GLMT-11, без `// DEVIATION` |
| ATYP=1 IPv4 | ✓ оба направления |
| ATYP=3 domain | ✗ e2e нет; policy «domain → REP=4, DNS нет» не закреплена — GLMT-06 |
| ATYP=4 IPv6 target | ✗ e2e нет (только upstream-facing через resocks5_net server) — GLMT-06 |
| DST.PORT=0 | upstream-facing: `port == 0` → Err (proxy.rs:103); parent-side не закреплён |
| UNAME/PASSWD ≤255 | ✓ wire-принудительно (u8); 255+concat покрыт unit'ом, e2e нет — GLMT-07 |

### HTTP CONNECT (RFC 7231/7235) — upstream-facing

| Случай | Статус |
|---|---|
| Успех = 2xx range vs только 200 | **не проверено, reference unavailable** — логика в resocks5-net 0.4.1 (GLMT-03) |
| Ответ без reason-phrase / «HTTP/1.1 200» | не проверено (внешний crate); e2e pin'ит только server-side байты |
| Case-insensitivity заголовков | не проверено (внешний crate) |
| Chunked/Content-Length в CONNECT-ответе | не проверено (внешний crate); по RFC 7231 §4.3.6 2xx на CONNECT тела не имеет |
| Basic credentials: user-id без `:` (RFC 7617) | ✓ proxy.rs:71–75 + тест `http://u%3Aname:p@…` → Err |
| Colon-rejoin (недавний фикс) | ✓ `http_credentials_rejoin_basic_halves_and_strip_marker`: `url=https` + `//x:` → `url=https://x`; `@` внутри пароля покрыт parse-тестом `p%40ss`; хвостовой-`:` амбiguity — GLMT-15 |
| Auth-заголовок в wire-формате (base64) | ✓ e2e `http_connect_preserves_pipelined_payload_through_transport` (реальный Basic header) |

### PT-spec (TOR_PT_*)

Референс spec.torproject.org офлайн недоступен; сверка по памяти спецификации и по поведению Go pt-библиотеки — помечено как **«conformance not verified, reference unavailable»** для спорных пунктов.

| Требование spec | Статус |
|---|---|
| §3.1 VERSION reply при общем протоколе | ✓ `VERSION 1` |
| §3.1 VERSION-ERROR no-version при отсутствии общего | **✗ не эмитится** — GLMT-01 (spec-mandated состояние отсутствует в коде и в тестах) |
| §3.2.1 ENV-ERROR при плохом env | **✗ не эмитится** — GLMT-02 |
| §3.3.1 CMETHOD / CMETHOD-ERROR / CMETHODS DONE | ✓ (`print_cmethod_error` для неизвестного транспорта) |
| §3.3.2 PROXY-ERROR при непригодном TOR_PT_PROXY | ✓ e2e `tests/proxy_error.rs::assert_rejected` — точная последовательность `VERSION 1` → `PROXY-ERROR …` pinned |
| §3.3.2 PROXY DONE при валидном | ✓ e2e `assert_transport_configured_with_proxy` |
| Пустой TOR_PT_PROXY = unset | реализовано; соответствует поведению Go pt, **conformance not verified, reference unavailable** |
| TOR_PT_PROXY с hostname (`socks5://example.com`) | отклоняется (только SocketAddr); допустимость hostname по spec — **not verified** |
| Non-UTF8 TOR_PT_PROXY | ✓ PROXY-ERROR без эха (`to_str().ok_or(())`); Windows e2e не покрыт — GLMT-16 |
| §3.3.3 TOR_PT_OUTBOUND_BIND_ADDRESS_* | **✗ отсутствует целиком**, без DEVIATION-комментария — GLMT-10 |
| §3.4 EXIT_ON_STDIN_CLOSE | ✓ (stdin_watch + lifecycle-тесты) |
| §3.5 args через SOCKS5 creds (marker `\0` / concat, cap 255) | ✓ реализация повторяет Go `rfc1929.go`; unit-тесты на все три формы + 255-границу |

### obfs4 wire

Diff obfs4-код не трогает (только version bump) — сверка констант проведена против цитируемых doc-комментариев репо:

| Константа | Значение в репо | Согласованность с doc/reference-формулой |
|---|---|---|
| MAX_SEGMENT_LENGTH | 1500 − (40 + 12) = 1448 | ✓ соответствует upstream-формуле в комментарии |
| FRAME_OVERHEAD | LENGTH_LENGTH + TAG_SIZE = 18 | ✓ |
| MAX_FRAME_PAYLOAD_LENGTH | 1448 − 18 = 1430 | ✓ |
| MESSAGE_OVERHEAD | 2 + 1 | ✓ (uint16 length + type byte) |
| MAX_MESSAGE_PAYLOAD_LENGTH | 1427 | ✓ |

Позитивные/негативные на границах: max payload и max+1 → `codecs/testing.rs:170–195` ✓. AUTH/ntor: негативные контролы есть — wrong-key (`handshake/integration.rs:232`), tamper (`codecs/testing.rs:245`), replay e2e с точным pin'ом варианта ошибки (`e2e_security.rs`) ✓. Сверка AUTH-констант и таймаутов с внешним upstream-obfs4 — **не выполнена, reference unavailable** (офлайн). «Polling-интервалы»: в obfs4 polling отсутствует; deadline'ы репо — локальная политика (`deadline_tests.rs`), внешний референс для сравнения недоступен.

### §F4 round-trip пары

| Пара | Round-trip покрытие |
|---|---|
| bridge-line Display/parse (base32/hex) | ✓ proptest + explicit (pre-existing, diff не трогал) |
| args encode_client_parameters ↔ parse_client_parameters | ✓ proptest `encode_then_parse_roundtrip` + `parse_never_panics` (pre-existing) |
| arg_string_from_creds (реконструкция) | частично: все три формы + 255-граница unit'ами; proptest над (uname, passwd)-доменом и e2e concat-формы нет — GLMT-07 |
| obfs4 state-serialization | вне diff; проверка не проводилась |

## Отсутствующие граничные тесты (готовые к реализации)

Формат: имя — модуль — вход — ожидание.

1. `socks5_parent_truncated_request_mid_domain_times_out` — socks_tests.rs — start_paused; полный greeting [5,2,0,2] + auth [1,1,u,1,0] + CONNECT header [5,1,0,3,len] с усечённым domain (нет байтов адреса) — по advance(SOCKS5_SETUP_TIMEOUT) handler Err с «proxy negotiation timed out», permit освобождён, socket закрыт. (Расширяет `assert_socks5_setup_timeout` на стадию request — сейчас там только пусто/1 байт/partial-HTTP.)
2. `socks5_parent_socks4_greeting_rejected_without_reply` — socks_tests.rs — вход [0x04,0x01,0,0,…) — handler Err; ни одного байта REP не записано (read → 0/ошибка). Фиксирует отказ без частичного ответа.
3. `socks5_parent_only_gssapi_gets_no_acceptable` — socks_tests.rs — вход [5,1,1] — parent читает [5,0xFF], затем handler Err и EOF. Закрывает 0xFF-строку RFC 1928.
4. `socks5_parent_domain_target_rejected_without_dns` — socks_tests.rs — ATYP=3, len, «example.com», порт 443 — REP=4 `[05 04 00 01 …]` (pin текущей policy «domain → host unreachable»); dokumentирует и GLMT-11 (REP=8 не эмитится).
5. `socks5_parent_ipv6_target_round_trips` — socks_tests.rs — ATYP=4, 16 байт ::1-эквивалента, порт — success reply + probe echo через реальный obfs4 bridge (по образцу `spawn_stack_with_active_tunnel`).
6. `socks5_parent_concat_form_over_255_bytes_end_to_end` — socks_tests.rs — arg string 255+21 байт, UNAME=255 байт, PASSWD=остаток (concat-форма, без marker) — success reply, args дошли до obfs4 builder'а (реальный handshake завершён). Сейчас concat-форма покрыта только unit'ом `arg_string_then_parse_yields_kv_map`.
7. `carrier_whole_operation_deadline_fires_without_any_reply` — proxy.rs tests — start_paused; TcpListener: accept и молчание; `Proxy::connect(...)` — advance(CONNECT_TIMEOUT + 1s) → Err; дополнительно: advance только до 9.9s → ещё pending (фиксирует «один whole-operation дедлайн», не per-stage). Закрывает GLMT-04.
8. `carrier_socks5_upstream_closes_after_method_selection` — proxy.rs tests — сервер отвечает [5,2] и drop — connect Err, без паники.
9. `carrier_socks5_upstream_closes_mid_auth` — proxy.rs tests — [5,2], затем 1 байт auth-ответа [1] и drop — Err.
10. `carrier_socks5_upstream_auth_failure_status_is_terminal` — proxy.rs tests — [5,2] → client creds → сервер отвечает [1,1] — Err. (Четвёртая стадия — «после auth до CONNECT reply» — покрывается #8-аналогом с drop после успешного auth.)
11. `carrier_domain_255_bytes_reaches_upstream_as_atyp3` — proxy.rs tests — домен ровно 255 байт против resocks5_net server: `request.target()` == домен; плюс `host.len() == 256` → Err без единого байта в сеть. Закрывает GLMT-07.
12. `carrier_fragmented_handshake_survives_one_byte_reads` — proxy.rs tests — реальный TcpStream, сервер дриффит method-selection [5,2] и auth [1,0] по 1 байту с flush — handshake завершается. §D1a adversarial chunking; при красном — баг resocks5_net, всплывший интеграцией (GLMT-08).
13. `http_connect_parent_without_authorization_gets_failure` — socks_tests.rs — CONNECT без Proxy-Authorization (creds=None, HTTP-путь) — transport строится с default args, obfs4 handshake против real bridge fail → REP=4, handler Err. Закрывает GLMT-09.
14. `proxy_parse_query_fragment_zoneid_and_degenerate_forms_rejected` — proxy.rs unit — `socks5://127.0.0.1:1080?x=1`, `…:1080#f`, `socks5://[::1%25eth0]:1080`, `socks5://a@b@c:1080`, `socks5://`, `socks5://@:1080`, `http://127.0.0.1` (без порта) — все Err. Код-ветки query/fragment/zone-id существуют, но не проверяются (GLMT-12).
15. `proxy_parse_socks5_credential_length_boundaries` — proxy.rs unit — uname/passwd ровно 255 → Ok; 256 → Err (http: >255 пароль → Ok — уже покрыто 300, оставить). Точная 255/256-граница не покрыта (GLMT-12/07).
16. `proxy_from_env_non_unicode_value_is_rejected` (портативный unit) — proxy.rs — `set_var` с не-UTF8 OsString → `from_env() == Err(())`; замыкает Windows-дыру cfg(unix) e2e-теста (GLMT-16).
17. `connect_rejects_port_zero_and_oversized_host_before_io` — proxy.rs tests — `connect("h", 0)` и `connect(&256-char, 443)` → Err мгновенно; слушателя нет, сеть не тронута. Закрывает GLMT-13.
18. `prefixed_reader_empty_prefix_and_byte_at_a_time` — socks_tests.rs — `Prefixed::new(vec![], inner)` читает сразу из inner; prefix из 4 байт доставляется по 1 байту на poll — содержимое и порядок сохранены (GLMT-14).
19. `http_credentials_trailing_colon_marker_collision_is_pinned` — socks_tests.rs — args, честно заканчивающиеся на `:` (`iat-mode=0:`) — текущее поведение: один `:` срезается; тест-pin + комментарий в `http_credentials` (GLMT-15).
20. (блокируется GLMT-01/02) `version_mismatch_prints_version_error` / `bad_env_prints_env_error` — tests/proxy_error.rs — spawn с `TOR_PT_MANAGED_TRANSPORT_VER=2` (или обоими TRANSPORTS) — ожидать `VERSION-ERROR no-version` / `ENV-ERROR …` на stdout и ненулевой exit. Реализуем после починки GLMT-01/02.

## Качество оракулов (Tier D)

- **§D1 — чисто.** В diff нет `should_panic`, float-ассертов, elapsed-порогов; таймаут-тесты используют `#[tokio::test(start_paused = true)]` + `advance()` (socks_tests.rs:13–48) — образцово: дедлайн проверен как поведенческое postcondition, не как производительность. Реальное время (5s timeout) используется только как hang-guard вокруг обязательного завершения — допустимо. Вакуумных тестов нет: константные ассерты (`accept_retry_delay(100) == 1s`, `[05 00 …]` байтовые pin'ы) — контрактные pin'ы внешнего wire-формата, не «константа == константа».
- **§D1a — сильные негативные контролы.** `invalid_pt_arguments_*` (parse fail + transport reject, без эха секретов), `unreachable_upstream_proxy_never_falls_back_to_direct_dial` (плюс проверка backlog моста — правильная методика), `client_handle_connection_no_success_reply_when_bridge_not_obfs4` (реальный obfs4 server как независимый oracle: plain TCP не завершит его handshake), `sdk_http_carrier_rejection_is_terminal` (rejected → сокет закрыт). Орacул «реальный obfs4 server» — из того же репо (reimplementation): межреализационная совместимость с Go obfs4proxy не проверяется CI — прекомит-риск вне diff, помечен в GLMT-03.
- **§D3 — fake_prng не течёт**: `crates/obfs4/src/lib.rs:369` — `#[cfg(test)] pub(crate) mod test_utils`, usage только под `cfg(test)`/в test_utils (grep-проверка). Масштаб: max-payload и max+1 в codecs/testing ✓. Gap: нет release-профиля тестов в CI — GLMT-18. Env-мутации в tests.rs под ENV_LOCK + restore-guard — приемлемо; лимит serial-подхода (см. §D1 testing.md: mutex сериализует только акварующие тесты) учтён — остальные тесты бинарника TOR_PT_* не читают (grep-проверка).
- **§D2 — размещение корректно**: unit-тесты приватных модулей — `#[path]`-модули внутри lib.rs под `cfg(test)`; integration `tests/proxy_error.rs` — только публичная поверхность + `env!("CARGO_BIN_EXE_lyrebird")` ✓; internals наружу не экспортируются.
- **§D4/§D5 — чисто**: CI гейтится на runner напрямую (`cargo test --locked --workspace --tests --no-fail-fast`), grep/head-фильтрации нет; скрипты с пайпами имеют `set -o pipefail`; Windows-matrix есть, per-job изоляция target-dir стандартна.

## Что не проверено

- **cargo не запускался** (правило ревью) — вывод о компилируемости/прохождении тестов не давался.
- **Исходник resocks5-net 0.4.1** недоступен офлайн (не извлечён из cache) — все внутренние поведения клиентского handshake (2xx range, case-insensitivity, chunked, фрагментация, обработка мусорной версии) — «conformance not verified, reference unavailable» (GLMT-03).
- **spec.torproject.org** и текст RFC — по памяти методики и Go pt-библиотеки; пустой TOR_PT_PROXY, hostname-форма TOR_PT_PROXY, точный текст §3.3.3 — не сверены с первоисточником.
- **upstream obfs4** (GitLab obfs4proxy) — AUTH-константы и таймауты не сверены с первоисточником (офлайн); сверены только внутренние формулы/комментарии репо.
- Windows-пути: non-UTF8 env e2e только unix (GLMT-16); реального запуска на Windows не производилось.
- `benches/lyrebird_bench.rs`, `examples/credentials.rs` — механические изменения под новый API, не ревьюились глубоко.
- obfs4 state-serialization round-trip — вне diff, не проверялся.

---

Итог: **P0: 0; P1: 2; P2: 9; P3: 8**.

P1 — оба спецификационные дыры control channel (VERSION-ERROR/ENV-ERROR): parent видит «молчаливую смерть» PT вместо spec-обязанной строки, диагноз по exit-коду невозможен. P2 — концентрируются вокруг неasm-покрытых стадий/границ новых proxy-путей и внешнего resocks5-net. Тестовая база в целом образцовая по §D1/§D1a — находки Tier D единичны и мелки.
