# Kotlin + Keycloak integration test

Небольшой учебный проект: Spring Boot API проверяет JWT, выданный Keycloak,
а права на эндпоинты определяет по ролям клиента `demo-api`.
Интерфейс входа и проверки прав находится в соседнем `cv-web`; этот модуль отдаёт только JSON API.

Стек: Kotlin 2.2.20, Gradle 8.14.3, Java 21, Spring Boot 3.5.16, Spring Security,
Keycloak 26.8.0. База приложения не нужна; Keycloak в этом примере использует H2.

## Быстрый запуск

Нужны Docker и Docker Compose v2. Порты 8080 и 8081 должны быть свободны.

```bash
cd keycloak-integration-test
docker compose up --build -d
docker compose logs -f
```

Первая сборка скачивает Gradle и зависимости. Kotlin API доступен на
**http://127.0.0.1:8080/api/public**, Keycloak — на **http://localhost:8081/**.
Запустите `../cv-web` по его README и откройте **http://127.0.0.1:5173/**.
Вход и регистрация открывают форму Keycloak; новый пользователь автоматически получает
роль `USER` клиента `demo-api`. Пароль вводится только в Keycloak.

| Учётная запись | Пароль | Роли в API |
| --- | --- | --- |
| `demo` | `demo123` | `USER` |
| `manager` | `manager123` | `USER`, `ADMIN` |

Админка Keycloak: **http://localhost:8081/admin/**, логин `admin`, пароль `admin`.
В ней выберите realm `demo`. Пользователь `manager` управлять Keycloak не может:
роль `ADMIN` относится только к нашему API.

Realm, клиенты, роли и пользователи импортируются из `keycloak/demo-realm.json`.
Изменения в админке сохраняются в Docker volume. Повторный запуск не перезаписывает
существующий realm. Если realm `demo` уже был импортирован до переноса UI в React, обновите регистрацию,
redirect URI и web origin клиента `demo-browser` без удаления пользователей:

```bash
python scripts/enable_registration.py --keycloak-url http://127.0.0.1:8081
```

Скрипт использует локальные учётные данные админа `admin` / `admin` из `compose.yml`.
Если они изменены, задайте переменные окружения `KEYCLOAK_ADMIN_USERNAME` и
`KEYCLOAK_ADMIN_PASSWORD`. Существующие пользователи и роли сохраняются.

Для повторного импорта с нуля удалите данные **учебного** Keycloak:

```bash
docker compose down -v
docker compose up --build -d
```

Обычная остановка с сохранением настроек: `docker compose down`.

## Локальный запуск API из IDE

Нужен JDK 21. Отдельно установленный Gradle не нужен — wrapper включён в репозиторий.

```bash
docker compose up -d --wait keycloak
./gradlew bootRun
```

В Windows используйте `gradlew.bat bootRun`. В IntelliJ IDEA откройте корень проекта,
выберите JDK 21 для Gradle и запустите `KeycloakDemoApplicationKt`.
Не запускайте контейнер API и `bootRun` одновременно на порту 8080.

## Что проверить

| Метод и путь | Доступ | Ожидаемое поведение |
| --- | --- | --- |
| `GET /api/public` | Всем | `200`, публичная информация |
| `GET /api/me` | Валидный access token | `200`, subject, username, email, роли и scopes |
| `GET /api/user` | Роль `USER` клиента `demo-api` | `200` для demo и manager |
| `GET /api/admin` | Роль `ADMIN` клиента `demo-api` | `403` для demo, `200` для manager |
| `GET /actuator/health` | Всем | `200`, состояние приложения |

Без токена защищённые эндпоинты возвращают `401` и `WWW-Authenticate: Bearer`.
Невалидный, просроченный или предназначенный другому API токен тоже даёт `401`.
При валидном токене без нужной роли возвращается `403`.
API разрешает только перечисленные маршруты и методы.

В `cv-web` нажмите «Мой профиль», USER или ADMIN до входа и после входа.
Затем выйдите и войдите вторым пользователем. Кнопка «Выйти» завершает SSO-сессию
в Keycloak. React хранит токены только в памяти вкладки; после перезагрузки страницы
или истечения access token (5 минут) нужно снова войти.

## Проверка через curl

Отдельный клиент `demo-cli` включает Direct Access Grants исключительно для локальных
проверок. React использует другой клиент и Authorization Code + PKCE, а не парольный grant.
В bash с установленным Python 3:

```bash
TOKEN=$(curl --fail --silent --show-error \
  -X POST http://localhost:8081/realms/demo/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'client_id=demo-cli' \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode 'username=demo' \
  --data-urlencode 'password=demo123' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -i http://127.0.0.1:8080/api/me -H "Authorization: Bearer $TOKEN"
curl -i http://127.0.0.1:8080/api/user -H "Authorization: Bearer $TOKEN"
curl -i http://127.0.0.1:8080/api/admin -H "Authorization: Bearer $TOKEN"
```

Для доступа к ADMIN получите токен с `username=manager`, `password=manager123`.
Пароли и выдача токенов находятся в Keycloak; своего `/login` у API нет.

## Тесты

```bash
./gradlew clean build
```

Тестам Gradle не нужен запущенный Keycloak или Docker: тестовый HTTP-сервер отдаёт
публичный RSA-ключ, а запросы проходят через настоящий JWT decoder и security filter chain.
Проверяются публичные маршруты, права, scopes, роль чужого клиента, realm role,
неверные/отсутствующие claims, issuer, audience, подпись и время действия.

Дополнительно, с запущенными Keycloak и API:

```bash
python3 scripts/smoke_test.py
```

В Windows: `python scripts/smoke_test.py`. Скрипт не требует сторонних Python-пакетов,
ждёт готовности сервисов и проверяет реальные токены обоих пользователей, ответы
200/401/403, отказ при ID token, refresh и невозможность обновить токен после logout.
Также проверяет браузерный Authorization Code + PKCE, CORS обмена токенов, SSO logout
и регистрацию нового пользователя с ролью `USER`. Временный аккаунт после проверки удаляется.
GitHub Actions выполняет сборку, тесты и эту проверку с реальным Keycloak.

## Как работает интеграция

1. React в `cv-web` перенаправляет браузер на Keycloak с PKCE challenge и случайным `state`.
2. После входа Keycloak возвращает одноразовый authorization code.
3. React обменивает code + verifier на токены и обращается к этому API через прокси `/auth-api`, передавая access token в заголовке `Authorization: Bearer ...`.
4. Spring Security получает ключи из JWKS и проверяет RSA-подпись, issuer, audience и время действия JWT.
5. `KeycloakAuthoritiesConverter` берёт `resource_access.demo-api.roles`,
   преобразует `USER`/`ADMIN` в `ROLE_USER`/`ROLE_ADMIN` и сохраняет `SCOPE_*`.
6. Security filter chain проверяет права на выбранный endpoint.

Три клиента разделяют задачи:

| Клиент | Назначение |
| --- | --- |
| `demo-api` | Resource server, целевая audience и роли приложения |
| `demo-browser` | Публичный клиент React, вход через Authorization Code + PKCE S256 |
| `demo-cli` | Публичный клиент только для локальных smoke-проверок |

У API нет client secret, своего хранилища паролей или сессий. CSRF отключён для
stateless Bearer API; токены из cookies он не принимает. Административные роли
realm или роли другого клиента доступа к API не дают.

Issuer всегда `http://localhost:8081/realms/demo`, в том числе внутри контейнера API.
Но JWKS контейнер API запрашивает по внутреннему адресу `http://keycloak:8080/...`.
Это позволяет сохранить правильную проверку `iss` и избежать обращения к самому API
через контейнерный `localhost`.

| Переменная окружения | Значение по умолчанию |
| --- | --- |
| `KEYCLOAK_ISSUER_URI` | `http://localhost:8081/realms/demo` |
| `KEYCLOAK_JWK_SET_URI` | `${issuer}/protocol/openid-connect/certs` |
| `KEYCLOAK_API_CLIENT_ID` | `demo-api` — audience и источник ролей |
| `KEYCLOAK_BROWSER_CLIENT_ID` | `demo-browser` |

Клиент `demo-browser` разрешает redirect URI `http://127.0.0.1:5173/` и web origin
`http://127.0.0.1:5173`. Если меняете адрес UI или Keycloak, обновите issuer,
`KC_HOSTNAME`, redirect URI и web origins в realm. Для уже импортированного realm
используйте скрипт выше либо админку Keycloak; повторный импорт его не перезапишет.

Logout прекращает сессию и возможность refresh, но уже выданный access token
остаётся действительным до истечения срока: API проверяет JWT локально.
Для немедленного отзыва понадобятся introspection или собственная проверка отзыва.

Это пример для локального обучения: `start-dev`, H2 и демонстрационные пароли.
Перед реальным использованием нужны HTTPS, PostgreSQL для Keycloak, защищённые
административные credentials и отключение `demo-cli`/Direct Access Grants.

Документация: [Keycloak Docker](https://www.keycloak.org/getting-started/getting-started-docker),
[Spring Security JWT Resource Server](https://docs.spring.io/spring-security/reference/6.5/servlet/oauth2/resource-server/jwt.html).
