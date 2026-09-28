# ANet VPN

ANet is a client and server for connecting private networks over the ANet Secure
Transport Protocol (ASTP). This repository contains the shared Rust core, Linux
server, desktop and Android client components, and the administrator panel.

## Происхождение

Этот проект начался как форк [ZeroTworu/anet](https://github.com/ZeroTworu/anet).
В исходную копию вошёл upstream-коммит `3f3a837` от 17 сентября 2026 года.
Дальше проект развивается в публичном репозитории
[igor04091968/anet-vpn](https://github.com/igor04091968/anet-vpn). История,
лицензия и уведомления исходного проекта сохранены; подробности — в
[`UPSTREAM.md`](UPSTREAM.md).

## Возможности

- Клиент и сервер поддерживают ChaCha20-Poly1305 и ГОСТ-алгоритм
  Кузнечик-MGM. Алгоритм задаётся в конфигурации; в клиентском профиле его
  можно выбрать отдельно для каждого сервера. Стороны должны использовать один
  и тот же алгоритм. Реализация ГОСТ здесь не является сертифицированным
  средством криптографической защиты.
- ASTP работает поверх QUIC, SSH, VNC, WebSocket и AHTTP. Доступные транспорты
  зависят от настроек конкретного сервера.
- Серверы могут проверять ключ клиента через `anet-auth` и выдавать ему
  конфигурацию с адресом и параметрами маршрутизации.
- Веб-панель управляет клиентами, группами, пулами серверов, маршрутами и
  настройками Telegram. Из профиля клиента можно отправить в Telegram ссылку на
  его конфигурацию и ссылку на приложение. Для этого клиент должен сообщить
  свой числовой Telegram chat ID и начать переписку с ботом.
- Есть Linux GUI и CLI, Android-библиотека и заготовка отдельного iOS-клиента.
  iOS-компоненты пока не представляют готовое приложение для установки.

Ссылка на конфигурацию даёт возможность скачать профиль без входа в панель.
Отправляйте её только нужному получателю и не добавляйте персональные ссылки,
ключи или рабочие конфиги в Git.

## Основные части

| Каталог | Назначение |
| --- | --- |
| `anet-common` | Общие протоколы, типы и криптографические примитивы |
| `anet-client-core` | Сетевое подключение и транспортный слой клиента |
| `anet-client-cli` | Консольный Linux-клиент |
| `anet-client-gui` | Графический клиент для Linux и Windows |
| `anet-mobile` | Rust-библиотека и JNI для Android-клиента |
| `anet-server` | Сервер ANet для Linux |
| `anet-auth` | API авторизации, управления клиентами и Telegram-доставки |
| `anet-webui` | Веб-интерфейс панели администратора |
| `anet-keygen` | Утилита для генерации ключей |
| `anet-ios` | Начальная заготовка iOS-приложения и Rust FFI |
| `ops/webui` | Шаблоны и инструкции локального WebUI-развёртывания |

## Сборка

Нужен стабильный Rust toolchain. Для сборки Linux GUI на Debian/Ubuntu
установите системные зависимости и соберите пакет:

```sh
sudo apt install libgtk-3-dev libappindicator3-dev protobuf-compiler libxdo-dev
cargo build --release -p anet-client-gui
```

Другие полезные команды из корня проекта:

```sh
cargo build --release -p anet-client-cli
make mob                 # Android JNI-библиотеки; нужен Android NDK и cargo-ndk
cargo build --release -p anet-client-gui  # GUI на текущей платформе, включая macOS
```

Полная карта развернутых сервисов находится в
[`docs/operations-current.md`](docs/operations-current.md). Инструкции по
Telegram-доставке и настройке WebUI — в [`ops/webui/README.md`](ops/webui/README.md).

## Релизы

Сборки публикуются на странице
[Releases](https://github.com/igor04091968/anet-vpn/releases). Перед установкой
проверьте описание релиза и контрольную сумму приложенного файла.

## Скриншоты

В `.assets/` лежат снимки интерфейсов Windows, Android и панели администратора.
