# ГОСТ: отдельный тест на gw

Сервис `anet-server-gost-test` использует UDP 2445, интерфейс
`anet-gost-test` и подсеть `10.23.0.0/24`. Рабочий `anet-server2` использует
UDP 993. Конфиг тестового сервиса хранится на gw с правами 600:
`/opt/anet/gost-test/server.toml`.

`prepare_config.py` берёт сертификат и ключ сервера из действующего конфига
на самом gw. Доступ задаётся отдельным списком отпечатков: профиль телефона
и проверочный клиент. Auth API и control plane в тесте отключены.
Перед запуском проверьте, что порт, интерфейс и подсеть свободны.

## Развёртывание

1. Собрать `cargo build --locked --release -p anet-server` и проверить SHA-256.
2. На gw установить бинарник, `prepare_config.py` и `firewall.sh` в
   `/opt/anet/gost-test/`; бинарник и firewall-скрипт должны быть исполняемыми.
   Unit установить как `/etc/systemd/system/anet-server-gost-test.service`.
3. Установить файл разрешённых отпечатков с правами 600, по одному на строку,
   и выполнить:

   ```sh
   sudo python3 /opt/anet/gost-test/prepare_config.py \
     --fingerprints /opt/anet/gost-test/allowed-fingerprints.txt
   ```

4. Выполнить `systemctl daemon-reload`, затем
   `systemctl enable --now anet-server-gost-test`. Проверить журнал и UDP 2445.
   Сервис добавляет адресные правила firewall при запуске и удаляет их
   при остановке; существующие правила не заменяются.

## Проверка

Поле профиля клиента: `crypto.algorithm = "kuznyechik-mgm"`.
Endpoint теста: `quic://gw.iri1968.ru:2445`. Профиль для рабочего UDP 993
хранится отдельно:
`profiles/gw-993-gost-stable-client.toml` в закрытом `anet-android-private`.

Проверочный Rust-тест использует клиентское ядро и реальный сервер через
UDP. Он не создаёт TUN и не меняет маршруты ноутбука:

```sh
ANET_PROBE_CONFIG=/secure/path/probe.toml ANET_PROBE_EXTERNAL=1.1.1.1 \
  cargo test --locked -p anet-client-core --lib live_quic_probe -- --ignored --nocapture
ANET_PROBE_CONFIG=/secure/path/probe.toml \
  cargo test --locked -p anet-client-core --lib live_quic_rejects_wrong_algorithm -- --ignored
```

Проверяются рукопожатие, ICMP-пакеты 84 и 1280 байт, выход через сервер,
сохранение соединения после 40 секунд простоя и отказ при несовпадении
алгоритмов. Реальное поведение Android и сети МТС проверяется на телефоне.

В серверном журнале успешного подключения должен быть `KuznyechikMgm`.
При захвате UDP можно проверить открытый префикс `ANETGOST1` в обоих
направлениях. Этот префикс сам по себе не доказывает шифрование и не
гарантирует, что внешняя система классификации распознает ГОСТ.

Режим использует Кузнечик-MGM для внешнего шифрования ANet. Подписи Ed25519,
обмен X25519, SHA-256 и внутренний QUIC/TLS сохраняются. Это не полностью
ГОСТ-криптографический стек и не утверждение о сертификации.

## Откат

```sh
sudo systemctl disable --now anet-server-gost-test
```

Остановка удаляет правила с комментарием `anet-gost-test`. Проверить
отсутствие UDP 2445 и сохранение `anet-server2` на UDP 993. Ключи,
конфиги, резервные копии и захваты трафика остаются на сервере.

## Рабочий UDP 993 после переключения 2026-09-25

`anet-server2` запускает новый бинарник с Кузнечиком-MGM из
`/opt/anet/anet-server`; конфиг `/opt/anet/server22.toml` сохранён с теми же
ключами сервера и клиентским списком доступа. MTU и максимальный QUIC MTU —
1300, GSO выключен, keep-alive — 7 секунд. Отдельный сервис 2445 и его ключи
не менялись.

Перед переключением `prepare_993_cutover.py` сохранил бинарник и конфиг в
`/opt/anet/backups/gost-cutover-20260925T161319Z`. Проверка клиента прошла:
адрес `10.22.0.2`, шлюз, внешний ICMP, повторная передача после 40 секунд
простоя; QUIC loss 0. Таймер автоматического отката остановлен после проверки.

Ручной откат рабочего UDP 993:

```sh
sudo /opt/anet/backups/gost-cutover-20260925T161319Z/rollback.sh --force
sudo systemctl is-active anet-server2
sudo ss -lun | grep ':993 '
```

Откат восстановит ChaCha-бинарник и исходный конфиг. Профиль 993 с ГОСТ после
отката не подключится; для него снова понадобится прежний профиль ChaCha.
