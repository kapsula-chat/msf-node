# AGENTS.md

## Назначение
Этот репозиторий содержит `kapsula-server`: MSF-ноду для приема, хранения и выдачи сообщений.
Основная цель агента: вносить минимальные и безопасные изменения без поломки wire-совместимости API.

## Технологии
- Go `1.24.x`
- HTTP: `gin-gonic/gin`
- Хранилище: `badger/v4`
- Криптография: `ed25519`, `edwards25519`

## Карта проекта
- `main.go`:
  - инициализация сервера и Badger
  - middleware (лимит размера, auth)
  - маршруты `/message`, `/device`, `/health`
  - graceful shutdown
- `messages.go`:
  - ключевая логика сообщений, pending-очередей и получения сообщений
  - валидация подписей, кросс-серверная доставка, DNS-резолв addressee
- `devices.go`:
  - регистрация/удаление/листинг устройств пользователя
- `types.go`:
  - структуры `Server`, `RawMessage`, `DeviceInfo`
- `scripts/buildx-build.sh`:
  - helper для multi-arch docker buildx

## Локальный запуск
- dev режим (по умолчанию не `PRODUCTION`): данные в `./data`
- production режим (`ENV=PRODUCTION`): данные в `/data`

Команды:

```bash
go run .
go build ./...
go test ./...
```

## Docker
```bash
docker build -t kapsula-server:local .
./scripts/buildx-build.sh <image> <tag>
./scripts/buildx-build.sh --push <image> <tag>
```

## API и инварианты, которые нельзя ломать
- Лимит размера тела: `MessageSize = 4096`.
- Заголовки аутентификации/подписи (`X-From`, `X-Rcpt`, `X-Signature`, `X-Timestamp`, `X-Device-ID`) обязательны для соответствующих endpoint.
- Формат ключей Badger:
  - `m:` message key
  - `d:` device key
  - `p:` pending key
- TTL сообщений и pending-записей: 7 дней.
- `/health` возвращает Prometheus text exposition (используется мониторингом).

## Правила изменения кода
- Перед изменениями прочитать целиком затронутый файл.
- Не менять формат ключей в Badger без явной задачи на миграцию.
- Не удалять проверки подписи и replay-защиту.
- Держать изменения малыми и локальными; избегать "рефакторинга заодно".
- После правок обязательно:
  1. `gofmt -w` на измененных файлах
  2. `go test ./...`
  3. `go build ./...`

## Environment variables
- `ENV=PRODUCTION` переключает директорию данных на `/data`.
- `KAPSULA_ACCESS_TOKEN` включает Bearer-auth для всех endpoint, кроме `POST /message`.
- `SHOW_NO_DEVICE` возвращает явную ошибку при отправке без зарегистрированных устройств.
- `SEND_PUSH` включает отправку push через `https://presence.kapsula.chat/push`.

## Что учитывать при ревью/доработках
- В коде есть сетевые вызовы (DNS, внешние HTTP); они влияют на latency и отказоустойчивость.
- Очередь записи в Badger асинхронная (`s.messages`), важно не блокировать writer-поток.
- Любые изменения в `/health` должны сохранять Prometheus-совместимый формат.
