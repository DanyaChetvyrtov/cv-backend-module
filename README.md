# Kotlin BFF + Keycloak + Python CV

Kotlin 2.2.20, Gradle 8.14.3, Java 21, Spring Boot 3.5.16 / Spring Security.
Этот модуль — **stateful BFF**, а не JWT resource server для браузера.

React обращается к BFF по `/api/*`. Kotlin выполняет Authorization Code + PKCE, хранит access/refresh-токены
в HTTP-сессии и отдаёт браузеру HttpOnly-cookie `BFFSESSION`. Python CV вызывается сервером по внутреннему HTTP.
Вход и регистрация используют формы Keycloak через серверные редиректы.

## Запуск

Запускайте единый Compose из [cv-complex-test](https://github.com/DanyaChetvyrtov/cv-root).
В модуле нет Compose-файлов. Корень запускает также Nginx/React, Python и Keycloak.
UI: **http://127.0.0.1:5173/**; Keycloak: http://localhost:8081/.
Учебные аккаунты: `demo / demo123` (USER), `manager / manager123` (USER, ADMIN).

Одноразовый `keycloak-init` вызывает [scripts/configure_bff.py](scripts/configure_bff.py):
создаёт/обновляет confidential-клиент `demo-bff`, PKCE, callback/logout, scope mappings и регистрацию;
отключает старые `demo-browser`/`demo-cli`. Существующие пользователи не удаляются.
Новым пользователям назначается только USER. Secret и BFF должны использовать одно значение.

## Контракт

| Метод и путь | Доступ / назначение |
| --- | --- |
| `GET /api/public` | Публичная информация без OAuth-конфигурации/токенов |
| `GET /api/health` | Публичная проверка CV через BFF |
| `GET /api/auth/login`, `GET /api/auth/register` | Начало входа / регистрации, без знания провайдера в React |
| `GET /api/auth/callback/keycloak` | Серверный OIDC callback |
| `GET /api/auth/csrf` | CSRF-токен и имена header/parameter |
| `GET /api/me` | Профиль cookie-сессии, без OAuth-токенов |
| `GET /api/user`, `GET /api/admin` | USER / ADMIN |
| `POST /api/vision/detect?confidence=0.25` | USER + CSRF; multipart-поле `image` |
| `POST /api/auth/logout` | CSRF; очистка cookie/сессии и OIDC logout |
| `GET /actuator/health` | Состояние BFF для Compose |

401 — нет сессии, 403 — нет прав либо неверный CSRF.
Bearer-токен из браузера не используется для аутентификации.
Сессия переживает перезагрузку страницы, idle timeout — 30 минут.
CSRF-токен обновляется после входа/logout; запрашивайте его перед изменяющим запросом.
GET logout не завершает сессию.

Spring проверяет state, nonce, RSA-подпись, issuer и audience ID token.
Роли берутся только из `resource_access.demo-api.roles` после проверенного OIDC login.
Refresh происходит на сервере перед защищёнными запросами; invalid_grant/invalid_token завершает сессию.
Logout перенаправляет браузер через end-session endpoint Keycloak, но React не выполняет token exchange.

## Настройки

| Переменная | Локальное значение / назначение |
| --- | --- |
| `KEYCLOAK_ISSUER_URI` | `http://localhost:8081/realms/demo`, публичный issuer/вход/logout |
| `KEYCLOAK_INTERNAL_BASE_URI` | По умолчанию issuer; в Compose — `http://keycloak:8080/realms/demo` |
| `KEYCLOAK_CLIENT_ID` | `demo-bff` |
| `KEYCLOAK_CLIENT_SECRET` | `local-bff-secret`, только для учебного стенда |
| `BFF_PUBLIC_URL` | `http://127.0.0.1:5173`, фиксированный origin callback/logout |
| `CV_SERVICE_URL` | `http://127.0.0.1:8000`; в Compose — `http://cv:8000` |
| `SESSION_COOKIE_SECURE` | `false` для локального HTTP; в production — `true` + HTTPS |

ClientRegistration задаёт backchannel-адреса явно: контейнер не пытается обращаться к своему `localhost`.
Профиль/токены разных пользователей и сессий хранятся отдельно.
В CV передаются только изображение и confidence, не cookie или Authorization.

## Разработка и тесты

Нужен JDK 21; wrapper Gradle включён. Поднимите Keycloak/инициализатор из корня общего проекта,
остановите контейнер `api`, запустите локальный Python CV по его README и затем из этого модуля:

```bash
./gradlew bootRun
./gradlew clean build
python3 -m unittest discover -s scripts -p 'test_*.py'
```

В Windows — `gradlew.bat` и `python`. Vite/Nginx на 127.0.0.1:5173 должен проксировать `/api/*` в локальный BFF.
Интеграционные тесты Kotlin не требуют реального Keycloak, Docker или весов модели:
локальные HTTP-серверы проверяют настоящий code exchange, PKCE, RSA/nonce, CSRF, сессии/роли, refresh, logout и multipart.
С работающим целым стендом:

```bash
python3 scripts/smoke_test.py
```

Этот тест проверяет настоящий Keycloak и CV через публичный origin.
Он временно сокращает срок access token для проверки refresh, восстанавливает настройку
и удаляет только созданный им временный аккаунт.

Для production нужны HTTPS, secret management, PostgreSQL для Keycloak и общий session store BFF при масштабировании.
MFA настраивается в Keycloak; в учебном realm принудительно не включена.

## Employee registry and face identification

The BFF owns employee metadata and 128-dimensional face templates in PostgreSQL. Liquibase creates the schema;
`DATABASE_URL`, `DATABASE_USERNAME`, `DATABASE_PASSWORD` configure the database (defaults: local database `employees`).
A local IDE launch needs a reachable PostgreSQL database; the root Compose database is internal.
The test profile uses H2 in PostgreSQL mode with the same migrations. Root CI additionally exercises real PostgreSQL.

* `GET /api/employees?page=0&size=20` — ADMIN, paged list (max size 100).
* `POST /api/employees` — ADMIN + CSRF, multipart `employeeCode`, `fullName`, optional `department`, `image`; returns 201 and metadata.
* `DELETE /api/employees/{id}` — ADMIN + CSRF, removes metadata and template; returns 204 or 404.
* `POST /api/employees/identifications` — USER + CSRF, multipart `image`.

Employee codes are normalized to uppercase ASCII letters/digits/underscore/hyphen. Registration rejects duplicate codes
or sufficiently similar existing faces with 409. A database row lock serializes enrollment across BFF instances.
Only the internal CV endpoint `/faces/embedding` returns a face vector; no embeddings or source photos are sent to React.
The BFF compares normalized SFace vectors using cosine similarity. `FACE_SIMILARITY_THRESHOLD=0.5` and
`FACE_AMBIGUITY_MARGIN=0.05` are server settings. They require calibration with your own enrollment/query/impostor photos.
A similarity score is not a probability. One template is stored per employee; matching currently scans the registry.
A changed model version returns 503 until employees are re-enrolled; incompatible templates are never compared.

Identification response:

```json
{"status":"matched","employee":{"id":"uuid","employeeCode":"EMP-001","fullName":"Иван Иванов","department":null,"createdAt":"timestamp"},"similarity":0.87,"threshold":0.5}
```

`unknown` or `ambiguous` returns `employee: null`. No face/multiple faces/small face returns 422;
malformed image returns 400, unsupported format 415, oversize image 413; unavailable CV returns 503.
An employee record does not create a Keycloak account. This photo demo has no liveness/anti-spoofing and does not open a physical gate.

Root CI verifies enrollment, recognition from a resized/re-encoded query, duplicate prevention, USER/ADMIN/CSRF,
invalid photos, deletion, and persistence after BFF/CV restart. The sample NASA astronaut photo is only a public-domain test fixture.
To include that scenario manually, install Pillow and pass `--face-image /path/to/test-face.png` to the smoke test.
