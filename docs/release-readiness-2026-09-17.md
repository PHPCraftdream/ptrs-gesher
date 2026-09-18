# Готовность следующего релиза — 2026-09-17

> Ниже — исходное ревью `9ecf4d4`. В следующем локальном проходе по поручению
> пользователя подготовлена версия 0.6.0 и исправлены RR19-01–05: версия и
> migration guide учитывают breaking change, rustls имеет нижний предел 0.23.45,
> публикация проверяет registry/source SHA, retry закреплён за исходным tag/SHA,
> changelog заполнен. Workflow использует Trusted Publishing для всех шести
> крейтов. Внешняя настройка publishers/environment остаётся за владельцем;
> значения приведены в [RELEASING.md](RELEASING.md). Удалённые операции не выполнялись.

## Локальная приёмка 0.6.0 — 2026-09-18

- Полный `release-check.py` завершился с `PASS`: debug/release tests со всеми
  features, clippy, fmt, MSRV 1.89, отдельные feature builds, Rust/Go interop,
  rustdoc, cargo-deny и сборка всех шести package archives.
- Semver gate распознаёт 0.6.0 как breaking release относительно 0.5.3;
  совместимость с 0.5.3 не заявляется. Новый carrier output проверяется отдельными
  consumer-тестами; мигрированный внешний consumer также успешно собран.
- Попытка выбрать rustls 0.23.44 во внешнем consumer отклоняется resolver;
  обычная сборка обновляет его до 0.23.45.
- 25 release-tooling regression tests прошли на Windows и Linux; actionlint
  проверил изменённые workflow. Тесты публикации используют mock cargo/registry
  и не выполняют загрузок.
- При инспекции архивов исправлены старые README с версией 0.3.0 и неоднозначный
  readme path umbrella-крейта; повторное пакетирование всех шести крейтов прошло.
- Trusted Publishing подготовлен в локальном workflow. Обмен OIDC и публикация
  не запускались: внешний environment и шесть publisher entries настраивает
  владелец по таблице в RELEASING.md. Коммит, push и теги не создавались.

## Исходное ревью

Проверен HEAD `9ecf4d4b5da8e606fe9c8122a6ab39481953478e`.
Все шесть опубликованных пакетов на crates.io имеют последнюю стабильную
версию 0.5.3; manifests текущего workspace также пока содержат 0.5.3.

**Вердикт: пока не публиковать.** Есть один блокер patch-релиза, три P2-пункта
подготовки публикации и один P3-пункт документации. При сохранении нового
carrier API рекомендована следующая согласованная версия **0.6.0**, не 0.5.4.
Production-код, manifests, lockfile и release workflow в этом ревью не менялись.

## Находки

### RR19-01 — P1 для patch-релиза: изменился публичный associated output type

Место: [WebTunnelClient::ClientTransport](../crates/webtunnel/src/lib.rs#L500).

В опубликованной 0.5.3 `OutRW` равен `PrefixStream<WebTunnelStream<TcpStream>>`
при любом допустимом `InRW`. Теперь он равен
`PrefixStream<WebTunnelStream<InRW>>`. Default type parameter сохраняет
совместимость TCP-варианта, но не всех ранее допустимых carrier типов.

Проверен внешний consumer с одинаковым кодом:

```rust
use ptrs::ClientTransport;
use tokio::io::DuplexStream;
use webtunnel::{PrefixStream, WebTunnelClient, WebTunnelStream};

pub fn use_wrapped_carrier(
    stream: <WebTunnelClient as ClientTransport<DuplexStream, std::io::Error>>::OutRW,
) -> PrefixStream<WebTunnelStream> {
    stream
}
```

С registry-зависимостями `ptrs-gesher-core =0.5.3` и
`ptrs-gesher-webtunnel =0.5.3`: `cargo check` завершился с 0. С path-зависимостями
на текущие пакеты: код 101, E0308, ожидается TcpStream-вариант, получен DuplexStream.
Это проверка совместимости consumer, а не падение тестового набора проекта.

При этом `cargo-semver-checks 0.50.0` с `--baseline-version 0.5.3
--release-type patch --workspace --exclude ptrs-gesher-examples --all-features`
прошёл для всех шести библиотек: этот случай автоматическая проверка пропустила.

**Перед выпуском:** сохранить исправленный supplied-carrier контракт, объявить
breaking change и перенести выпуск на 0.6.0; для типизированного carrier
использовать `WebTunnelStream<Carrier>`, для явного URL dial — `connect_url()`.
Если требуется именно 0.5.4, нужен совместимый API-адаптер и повторная проверка
consumer. Для 0.x изменение первой ненулевой компоненты отделяет несовместимые
версии по [правилам Cargo](https://doc.rust-lang.org/cargo/reference/semver.html#change-categories).

### RR19-02 — P2: исправленная версия rustls не обеспечена для downstream

Место: [rustls dependency](../crates/webtunnel/Cargo.toml#L23).

Workspace lockfile выбирает исправленный rustls 0.23.45, однако требование
`version = "0.23"` допускает уязвимые версии. Во внешнем consumer текущего
WebTunnel выполнен `cargo update -p rustls --precise 0.23.44`: resolver успешно
выбрал 0.23.44 для WebTunnel, tokio-rustls и Hickory. Lockfile репозитория
при этом не изменялся. Пользователь с уже существующим lockfile может сохранить
такую зависимость после обновления нашей библиотеки.

[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)
относит 0.23.44 к затронутым версиям; исправление доступно начиная с 0.23.45.
Это замечание о доставке исправления потребителю, а не утверждение об успешной
атаке или об уязвимости текущей сборки с repository lockfile.

**Перед выпуском:** задать совместимый нижний предел `rustls = "0.23.45"`
и проверить разрешение зависимостей во внешнем consumer. Одной проверки
`cargo deny` на нашем lockfile недостаточно для этой гарантии.

### RR19-03 — P2: publish.sh превращает посторонний отказ в успех

Место: [обработка already exists](../.github/scripts/publish.sh#L36).

Широкий regex принимает любую строку `already exists` и завершает скрипт с 0,
не проверяя наличие конкретной версии конкретного пакета в registry.
Изолированный запуск с mock cargo, без сетевой публикации, воспроизвёл:

```text
cargo: error: Cannot create a file when that file already exists. (os error 183)
cargo exit: 101
publish.sh: ALREADY ON CRATES.IO: ptrs-gesher (skipping)
publish.sh exit: 0
```

Так файловый/локальный отказ может дать зелёный publish step, хотя пакет не
загружен. Особенно заметно это на последнем пакете, за которым уже нет другого
publish step, способного обнаружить отсутствующую зависимость.

**Перед выпуском:** не классифицировать ошибки по общему `already exists`;
подтверждать точные package/version через registry, а остальные отказы
возвращать с ненулевым кодом. Добавить отрицательный сценарий локальной ошибки.

### RR19-04 — P2: ручное возобновление выпуска не фиксирует исходную ревизию

Места: [workflow_dispatch](../.github/workflows/release.yml#L12),
[checkout публикации](../.github/workflows/release.yml#L50),
[проверка только номера версии](../.github/workflows/release.yml#L61).

Manual dispatch принимает только `version`; checkout использует ref события,
а не обязательно исходный `vX.Y.Z`. Это соответствует
[default ref actions/checkout](https://github.com/actions/checkout/blob/v4/action.yml).
Комментарии workflow прямо предлагают retry с новой main-ветки.

Если часть пакетов уже загружена с коммита A, а retry запущен на B с теми же
номерами версий, старые пакеты будут пропущены, остальные — опубликованы из B.
Сборка и тесты проверяют полный workspace B, а не реально получившуюся смесь
A/B. Проверка совпадения чисел версий этого не обнаруживает.

**Перед выпуском:** закрепить source SHA/tag для всей серии публикаций и
проверять его при retry. Обновление самой логики workflow можно выполнять
отдельно от checkout публикуемых исходников. Сценарий подтверждён устройством
workflow; реальная частичная публикация не запускалась.

### RR19-05 — P3: Unreleased не описывает полный объём и миграцию

Место: [CHANGELOG.md](../CHANGELOG.md#L8).

Unreleased содержит ранние изменения, но не описывает новый carrier contract,
разделение SOCKS/SMETHOD, statefile API и Go numeric IAT, ciphertext IAT scheduler,
effective server configuration, последние изменения logging/lifecycle и
durability retry. Часть миграции есть в [VALIDATION.md](VALIDATION.md), однако
пользователь release notes не получает полного списка поведенческих изменений.

**Перед выпуском:** дополнить changelog, явно пометить RR19-01, связать release
notes с migration guide и закрыть статусы уже исправленных пунктов прошлых ревью.
Датированный раздел и согласованный bump шести пакетов/внутренних требований
выполнять после выбора версии, а не в рамках этого ревью.

## Что подтверждено

- [CI текущего HEAD](https://github.com/PHPCraftdream/ptrs-gesher/actions/runs/35233389628)
  завершился успешно: все 9 jobs, включая Windows/Linux tests, MSRV 1.89,
  clippy всех targets/features, rustdoc, примеры, fmt и line limits.
  [Coverage](https://github.com/PHPCraftdream/ptrs-gesher/actions/runs/35233389650)
  тоже зелёный. Это проверенные результаты CI, не повторный локальный полный прогон.
- В этом проходе заново выполнен Windows Rust/Go interop: оба направления,
  IAT 0/1/2, 4 KiB request/reply, malformed reply — PASS.
- Автоматическое сравнение с registry 0.5.3 — PASS, с ограничением RR19-01.
- Положительный/отрицательный consumer compile probe подтвердил RR19-01.
- Внешний dependency resolver подтвердил RR19-02; mock publish подтвердил RR19-03.
- `cargo package --workspace --exclude ptrs-gesher-examples --list --locked
  --allow-dirty` прошёл. В списках нет `.target-local`, `tools/interop/test.txt`,
  файлов логов или PEM. Это проверка состава, не новая сборка всех архивов.
- PT18-01 исправлен в `a605764`: reader result и echo task наблюдаются тестом.
  PT18-02 исправлен в `8151427`: собственная публикация учитывается после
  directory-sync failure; есть regression с однократным отказом и retry.
  Старый round-18 отчёт описывает более ранний HEAD и не переоткрывает эти пункты.

## Граница заключения и оставшаяся приёмка

Это ограниченное release-readiness ревью API, поставляемых зависимостей,
миграции, последних исправлений и publication workflow. Полный криптографический
аудит, все FFI/unsafe пути, Android и все runtime-комбинации не проверялись.
Experimental server остаётся явно незавершённой опцией, не обещанием готового
production PT-server. Registry credentials и права публикации не проверялись.

После исправления находок и подготовки согласованной версии нужны проверки
именно окончательного release commit: release tests, interop, API consumer,
MSRV/features, audit зависимостей и сборка всех package archives. Старые
release/packaging результаты от 15 сентября этому commit не приписываются.
`.target-local/` и `tools/interop/test.txt` не изменялись и не включались в отчёт
как дефекты production-кода. Коммитов, push, тегов и публикаций в этом проходе нет.
