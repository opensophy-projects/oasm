# open-appsec: обучение/проверка на собственных payloads

## Короткий вывод

В этих репозиториях нет публичного пайплайна, который берет текстовые payloads и переобучает supervised ML-модель open-appsec офлайн. По README open-appsec использует две модели: supervised-модель, обученную офлайн авторами проекта на миллионах malicious/benign запросов, и unsupervised-модель, которая строится в реальном времени на трафике конкретного защищаемого приложения. Поэтому готовые payloads из `newpayloads-newpayloads` правильно использовать не как прямой датасет для `fit()`, а как тестовый/валидационный набор: прогонять их HTTP-запросами через стенд open-appsec, собирать вердикты, переводить политику из `detect-learn` в `prevent-learn`, а результаты false/true positive оформлять через исключения/тюнинг и, при необходимости, добавлять очищенные payloads в наборы `mgm-web-attack-payloads-main`.

## Что уже есть в проекте

- `openappsec-main` описывает архитектуру ML: сначала supervised-модель сравнивает запрос с известными глобальными паттернами атак, затем подозрительные/high-risk запросы оцениваются unsupervised-моделью окружения.
- В этом же README сказано, что basic supervised-модель поставляется в репозитории, advanced-модель скачивается отдельно из портала, а unsupervised-модель строится в реальном времени в защищаемом окружении.
- `smartsync-main` отвечает за корреляцию learning data между несколькими агентами и доставку unified learning model для каждого asset.
- `smartsync-tuning-main` отвечает за корреляцию данных и создание tuning suggestions, улучшающих appsec learning model.
- `mgm-web-attack-payloads-main` — это не trainer, а коллекция для проверки WAF: простые текстовые списки `true-positives.txt`/`false-positives.txt`, которые удобно запускать через Nuclei или WAF Efficacy Framework.

## Анализ `newpayloads-newpayloads`

Команда анализа считала непустые строки без комментариев из текстовых файлов `newpayloads-newpayloads/payloads template` и сравнила их с `mgm-web-attack-payloads-main/nuclei/payloads` по точному совпадению строки после `strip()`.

Итог:

| Метрика | Значение |
|---|---:|
| Файлов в `newpayloads-newpayloads/payloads template` | 609 |
| Бинарных/не UTF-8 файлов, пропущенных анализом строк | 72 |
| Непустых строк-payloads | 1,845,231 |
| Уникальных строк-payloads | 1,788,998 |
| Внутренних дублей, лишних строк | 56,233 |
| Уникальных точных дублей с `mgm-web-attack-payloads-main` | 459 |
| Строк в `mgm-web-attack-payloads-main/nuclei/payloads` | 37,071 |
| Уникальных строк в `mgm-web-attack-payloads-main/nuclei/payloads` | 37,065 |

Дубли/пересечения по категориям верхнего уровня:

| Категория `newpayloads` | Строк | Внутренних дублей-строк | Пересечений с `mgm` |
|---|---:|---:|---:|
| Command Injection | 1,354 | 408 | 246 |
| SQL Injection | 1,648 | 157 | 215 |
| Fuzzing | 1,111,348 | 13,274 | 54 |
| XML_External_Entities | 192 | 52 | 4 |
| Web-Shells | 49,221 | 26,277 | 2 |
| Usernames | 659,612 | 47,305 | 1 |
| Остальные категории вместе | 21,856 | 15,760 | 0 |

### Стоит ли добавлять payloads

Да, но не все подряд.

Добавлять стоит:

1. Категории, которых почти нет в `mgm-web-attack-payloads-main`: SSRF, GraphQL Injection, Prototype Pollution, Open Redirect, HTTP Request Smuggling, WebSocket attacks, JWT attacks, NoSQL, template injection, path normalization bypass.
2. Новые payloads из SQLi/cmdexe/XXE только после дедупликации, потому что именно там основное пересечение с `mgm`.
3. Только строки, которые реально являются HTTP-пayload/частью HTTP-запроса и дают проверяемое ожидаемое поведение.

Добавлять не стоит без отдельной подготовки:

1. Огромные wordlists `Fuzzing`, `Usernames`, `User-Agents`: они больше подходят для brute-force/fuzzing, а не для обучения WAF-вердиктов; их лучше хранить отдельно и использовать выборочно.
2. Полные web shells, архивы, картинки, `.jar`, `.zip`, `.tar`, бинарники и PoC-скрипты: это не однострочные HTTP payloads для текущей структуры `mgm-web-attack-payloads-main`.
3. Дубли внутри `newpayloads` и точные дубли с `mgm`.
4. Payloads без контекста параметра/метода/заголовка, если из одной строки нельзя понять, как отправить корректный HTTP-запрос.

## Как подготовить payloads к использованию

1. Сделать staging-каталог, не изменяя исходники:

   ```bash
   mkdir -p /tmp/openappsec-payloads-clean/{sqli,cmdexe,xxe,ssrf,graphql,prototype_pollution,open_redirect,request_smuggling,websocket,jwt,nosqli,template_injection,traversal}
   ```

2. Вытащить строки из нужных категорий, убрать пустые строки и комментарии, дедуплицировать:

   ```bash
   python3 - <<'PY'
   from pathlib import Path
   import re

   src = Path('newpayloads-newpayloads/payloads template')
   out = Path('/tmp/openappsec-payloads-clean')
   mapping = {
       'SQL Injection': 'sqli',
       'Command Injection': 'cmdexe',
       'XML_External_Entities': 'xxe',
       'Server_Side_Request_Forgery': 'ssrf',
       'GraphQL_Injection': 'graphql',
       'Prototype_Pollution': 'prototype_pollution',
       'Open_Redirect': 'open_redirect',
       'HTTP_Request_Smuggling': 'request_smuggling',
       'WebSocket Attacks': 'websocket',
       'JWT_Attacks': 'jwt',
       'NoSQL_Injection': 'nosqli',
       'Template_Injection': 'template_injection',
       'Path_Normalization_Bypass': 'traversal',
   }

   for folder, category in mapping.items():
       lines = set()
       for p in (src / folder).rglob('*'):
           if not p.is_file():
               continue
           try:
               text = p.read_text(errors='strict')
           except Exception:
               continue
           for line in text.splitlines():
               s = line.strip()
               if s and not s.startswith('#'):
                   lines.add(s)
       (out / category).mkdir(parents=True, exist_ok=True)
       (out / category / 'true-positives.candidate.txt').write_text('\n'.join(sorted(lines)) + '\n')
   PY
   ```

3. Убрать точные дубли с `mgm-web-attack-payloads-main`:

   ```bash
   python3 - <<'PY'
   from pathlib import Path
   mgm = set()
   for p in Path('mgm-web-attack-payloads-main/nuclei/payloads').rglob('*.txt'):
       for line in p.read_text(errors='ignore').splitlines():
           s = line.strip()
           if s and not s.startswith('#'):
               mgm.add(s)

   for p in Path('/tmp/openappsec-payloads-clean').rglob('true-positives.candidate.txt'):
       kept = []
       for line in p.read_text(errors='ignore').splitlines():
           s = line.strip()
           if s and s not in mgm:
               kept.append(s)
       p.with_name('true-positives.new-only.txt').write_text('\n'.join(kept) + '\n')
   PY
   ```

4. Ручная ревизия: разделить `true-positives.new-only.txt` на:
   - `true-positives.txt` — payload должен считаться атакой;
   - `false-positives.txt` — строка легитимна и нужна для проверки, что WAF не блокирует нормальный ввод;
   - `reject.txt` — мусор, wordlist, полный файл web shell, бинарь, скрипт, строка без HTTP-контекста.

## Как “обучить” open-appsec на этих payloads

### Вариант A: локальное обучение unsupervised-модели через трафик

1. Поднять тестовый стенд open-appsec перед тестовым приложением, а не перед production.
2. Включить режим `detect-learn`, чтобы open-appsec учился и логировал, но не ломал стенд блокировками.
3. Прогнать нормальный benign-трафик приложения: логины, формы, API, загрузки файлов, GraphQL/WebSocket, реальные user agents. Это важнее, чем сразу стрелять атаками: unsupervised-модель должна увидеть норму именно вашего приложения.
4. Прогнать подготовленные malicious payloads как HTTP-запросы по нужным местам: query parameter, JSON body, XML body, path, headers, cookies, upload filename/content-type и т.д.
5. Собрать логи/вердикты open-appsec и матрицу результатов:
   - expected `true-positive`, detected/blocked = хорошо;
   - expected `true-positive`, allowed = false negative, нужен новый тест-кейс/правило/исключение в сторону усиления;
   - expected `false-positive`, detected/blocked = false positive, нужен tuning/исключение;
   - expected `false-positive`, allowed = хорошо.
6. После стабилизации модели и тюнинга переключить политику на `prevent-learn` с консервативным `minimum-confidence: high`, затем при необходимости ужесточать.

### Вариант B: расширить тестовый набор `mgm-web-attack-payloads-main`

Если цель — не обучение модели в runtime, а воспроизводимая проверка качества WAF, добавляйте отобранные строки в структуру `mgm-web-attack-payloads-main/nuclei/payloads/<category>/true-positives.txt` и `false-positives.txt`, а для новых категорий создавайте соответствующие Nuclei templates. Это даст повторяемый regression-test: одни и те же payloads можно запускать на разных версиях open-appsec и сравнивать результат.

## Как передать обученную модель на другой ПК/сервер/пользователям

Практически переносить нужно не исходную supervised-модель, а состояние runtime-обучения и конфигурацию:

1. Использовать одинаковую версию open-appsec/agent и одинаковую policy на всех серверах.
2. Если используется SaaS/central management, подключить агентов к одному management/asset — learning/tuning должен распространяться централизованно штатным способом.
3. Если используется self-managed вариант с smartsync, хранить и переносить persistent storage smartsync/smartsync-shared-files и данные агента, потому что smartsync отвечает за unified learning model для asset.
4. Для контейнерного standalone-агента не запускать его без persistent volumes: README показывает volumes для `/etc/cp/conf`, `/etc/cp/data`, `/var/log/nano_agent`; именно их нужно бэкапить и переносить вместе с policy.
5. Перед переносом остановить агент/сервисы, чтобы получить консистентную копию:

   ```bash
   docker stop agent-container
   tar -C /home/admin/agent -czf openappsec-trained-state.tgz conf data logs
   docker start agent-container
   ```

6. На новом сервере распаковать архив в такой же путь и запустить агент с теми же volume mappings:

   ```bash
   mkdir -p /home/admin/agent
   tar -C /home/admin/agent -xzf openappsec-trained-state.tgz
   docker run -d --name=agent-container --ipc=host \
     -v=/home/admin/agent/conf:/etc/cp/conf \
     -v=/home/admin/agent/data:/etc/cp/data \
     -v=/home/admin/agent/logs:/var/log/nano_agent \
     -it agent-docker /cp-nano-agent --standalone
   ```

7. Для передачи другим пользователям лучше передавать не только state archive, но и:
   - версию образа/пакета open-appsec;
   - `local_policy.yaml`/CRD/Helm values;
   - список payloads и expected labels;
   - changelog тюнинга: какие события признаны false positive/true positive и почему.

## Как говорить модели, что событие false positive или true positive

В open-appsec это не выглядит как интерактивная команда “переобучи на этой строке”. Практический цикл такой:

1. Сначала каждому тесту задается expected label в вашем наборе:
   - malicious payload → `true-positive` expected;
   - benign строка/запрос → `false-positive` expected, если WAF ее ошибочно ловит.
2. Запускаете тесты через WAF и сохраняете фактический результат.
3. Для false positive:
   - убедиться, что запрос действительно легитимен для вашего приложения;
   - добавить исключение/tuning suggestion через доступный способ управления open-appsec: SaaS Web UI, декларативная политика, Helm/CRD или локальный policy file;
   - повторить тест и убедиться, что запрос больше не блокируется, но похожие атаки все еще ловятся.
4. Для true positive:
   - ничего “разрешающего” не добавлять;
   - оставить/добавить payload в `true-positives.txt`;
   - если WAF не поймал payload, оформить его как regression/failure case и использовать для усиления политики/нового тестового template.
5. После каждого изменения policy/tuning прогонять полный набор `true-positives` и `false-positives`, иначе можно исправить один false positive и случайно открыть bypass.

## Рекомендуемый рабочий процесс

1. Не добавлять всю папку `newpayloads-newpayloads` в модель/тесты сразу.
2. Сначала взять категории с максимальной ценностью и низким пересечением: SSRF, GraphQL, Prototype Pollution, Open Redirect, Request Smuggling, WebSocket, JWT, NoSQL, Template Injection.
3. Для SQLi и Command Injection сначала убрать 461 точное пересечение суммарно по этим двум категориям.
4. Исключить большие brute-force wordlists, user agents, usernames, web shell repositories и бинарные файлы из первичного набора.
5. Сформировать маленький, понятный smoke-набор на 20-100 payloads на категорию.
6. Поднять стенд `detect-learn`, прогнать benign-трафик, потом malicious-трафик.
7. Зафиксировать baseline-отчет.
8. Добавить tuning для false positives.
9. Переключить на `prevent-learn` и повторить regression.
10. Только после этого переносить persistent state/policy на другой сервер или подключать несколько агентов через central management/smartsync.

## Быстрый старт, если сейчас есть только Docker

Для первого стенда проще выбрать **NPM + open-appsec**, а не собирать отдельный NGINX + attachment + agent вручную. Причины:

- В `open-appsec-npm-master` уже есть готовый `docker-compose.yaml` с двумя контейнерами: `nginx-proxy-manager-attachment` и `appsec-agent`.
- NPM Web UI уже содержит переключатель open-appsec для каждого Proxy Host, выбор `Detect-Learn`/`Prevent-Learn`, `minimum confidence` и страницу `Security Log`.
- В compose уже предусмотрены persistent volumes для конфигурации, learning data и логов: `./appsec-config`, `./appsec-data`, `./appsec-logs`, `./appsec-localconfig`.
- Для твоей задачи нужен быстрый цикл “создал host → включил WAF → прогнал payloads → посмотрел Security Log”, а NPM дает это быстрее, чем чистый NGINX.

### Минимальный стенд

1. Создай рабочую папку и зайди в нее:

   ```bash
   mkdir -p ~/openappsec-lab
   cd ~/openappsec-lab
   ```

2. Скопируй готовые compose/policy из репозитория:

   ```bash
   cp /workspace/oas1/open-appsec-npm-master/deployment/docker-compose.yaml ./docker-compose.yaml
   mkdir -p appsec-localconfig
   cp /workspace/oas1/open-appsec-npm-master/deployment/local_policy.yaml ./appsec-localconfig/local_policy.yaml
   ```

3. В `docker-compose.yaml` поменяй `user@email.com` на свой email или удали строку `user_email=...`.

4. Подними NPM + open-appsec:

   ```bash
   docker compose up -d
   docker ps
   ```

5. Открой NPM UI:

   ```text
   http://<IP_ТВОЕГО_СЕРВЕРА>:81
   ```

   Дефолтный логин для первого входа из README NPM-интеграции:

   ```text
   admin@example.com
   changeme
   ```

6. Подними любой тестовый backend, чтобы было куда проксировать атаки. Самый простой вариант:

   ```bash
   docker run -d --name vulnerable-backend --network openappsec-lab_default vulnerables/web-dvwa
   ```

   Если папку назовешь не `openappsec-lab`, имя compose-сети будет другим: посмотри его через `docker network ls` и подставь сеть вида `<папка>_default`. Если не хочешь DVWA, можно начать с обычного echo/httpbin-like сервиса, но для WAF-тестов лучше иметь приложение с реальными URL, query, form и body.

7. В NPM создай `Proxy Host`:
   - `Domain Names`: домен или IP/hostname, по которому будешь стрелять тестами;
   - `Forward Hostname / IP`: `vulnerable-backend`;
   - `Forward Port`: `80`;
   - включи open-appsec;
   - сначала выбери `Detect-Learn`, чтобы видеть события и не блокировать все подряд;
   - `Minimum confidence`: начни с `High`.

8. Подожди до 30 секунд после сохранения настроек — README предупреждает, что изменения конфигурации open-appsec из NPM UI применяются не мгновенно.

9. Сначала прогони нормальный трафик:

   ```bash
   curl -i 'http://<host>/'
   curl -i 'http://<host>/?q=hello'
   ```

10. Потом прогони маленький smoke-набор payloads:

   ```bash
   curl -i 'http://<host>/?id=1%20OR%201=1'
   curl -i 'http://<host>/?file=../../../../etc/passwd'
   curl -i 'http://<host>/?url=http://169.254.169.254/latest/meta-data/'
   ```

11. Смотри события:

   ```bash
   docker logs appsec-agent --tail=200
   tail -f ./appsec-logs/* 2>/dev/null
   ```

   Также открой пункт **Security Log** в модифицированном NPM UI.

### Когда переходить на отдельный NGINX + open-appsec

Отдельный NGINX + open-appsec имеет смысл, когда:

- тебе нужно повторить production-конфиг NGINX без NPM;
- нужны кастомные `location`, headers, auth, upstream-балансировка, Lua/njs и т.п.;
- тесты должны максимально соответствовать реальному reverse proxy;
- нужно собирать/патчить attachment или agent.

Для старта с payloads это лишнее. Начни с NPM + open-appsec, получи первые Security Logs и матрицу true/false positive, а потом уже переноси найденный workflow на чистый NGINX, если понадобится.

### Практический первый день работ

1. Поднять NPM + open-appsec по compose.
2. Поднять тестовый backend.
3. Создать Proxy Host и включить `Detect-Learn`.
4. Прогнать 20-30 нормальных запросов.
5. Взять 10 SQLi, 10 command injection, 10 SSRF, 10 traversal payloads.
6. Прогнать их через `curl` или Nuclei.
7. Сохранить таблицу результатов: payload, URL, expected label, actual action, confidence, log/event id.
8. Все false positives не “скармливать модели”, а оформлять как tuning/exclusion/policy change.
9. После исправлений повторить прогон.
10. Только когда false positives под контролем, переключать тестовый Proxy Host на `Prevent-Learn`.

## Production-подход: автоматический прогон с отдельного сервера

Если цель — не игрушечный lab, а production/prod-like проверка, схема должна быть такой:

```text
[payload-runner server]  --->  [public/canary domain]  --->  [NPM + open-appsec в Detect-Learn]  --->  [production-like backend]
```

Ключевая идея: **не “учить” production на всём подряд и не блокировать боевой трафик**, а прогонять заранее размеченные payloads через отдельный домен/route/tenant/canary-backend под `Detect-Learn`, собирать события open-appsec и сравнивать их с твоей внешней разметкой `expected_label=true-positive`.

### Можно ли одной командой слать payloads и помечать их как реальные атаки?

Частично да:

- можно одной командой слать все payloads с отдельного сервера;
- можно каждому запросу добавить заголовки `X-OAS-Test-Run`, `X-OAS-Payload-Id`, `X-OAS-Expected-Label: true-positive`;
- можно сохранить локальный JSONL/CSV с тем, какой payload, из какого файла и с каким expected label был отправлен;
- потом эти `payload_id`/`run_id` искать в open-appsec/NPM Security Logs и строить отчет.

Но важно: **это не то же самое, что встроенная команда open-appsec “пометь событие как true positive и переобучи supervised-модель”**. В открытых репозиториях такой публичный offline-trainer/label-ingestion pipeline не найден. Поэтому “пометка” делается в твоем внешнем test report: expected true-positive сравнивается с actual detect/prevent event. False positives затем исправляются policy/tuning/exclusions, а false negatives идут в backlog тестов/усиления политики.

### Что сделать на production/prod-like стороне

1. Выделить отдельный host, например:

   ```text
   waf-train.example.com
   ```

   Не направляй payload-runner сразу в основной `www.example.com`, если там живые пользователи.

2. В NPM создать отдельный `Proxy Host` для этого host.

3. Включить open-appsec для этого Proxy Host в режиме `Detect-Learn`.

4. `Minimum confidence` начать с `High`.

5. Backend лучше сделать production-like, но безопасный:
   - staging-копия приложения;
   - read-only окружение;
   - canary route, который не меняет реальные данные;
   - отдельная БД/tenant;
   - выключенные email/SMS/payment integrations.

6. В логах включить достаточную детализацию для корреляции: URL path/query и detect/prevent events. В стандартном `local_policy.yaml` уже включены `detect-events`, `prevent-events`, `url-path`, `url-query`, а stdout логов настроен как JSON.

### Команда запуска с другого сервера

В репозиторий добавлен простой runner:

```bash
python3 /workspace/oas1/scripts/payload_replay_runner.py \
  --base-url 'https://waf-train.example.com/search' \
  --payload-file '/tmp/openappsec-payloads-clean/sqli/true-positives.new-only.txt' \
  --payload-file '/tmp/openappsec-payloads-clean/cmdexe/true-positives.new-only.txt' \
  --param q \
  --method GET \
  --expected-label true-positive \
  --rate 2 \
  --limit 200 \
  --output runs/run-001.jsonl \
  --i-am-authorized
```

Что делает runner:

- читает один или несколько payload-файлов;
- пропускает пустые строки, комментарии и точные дубли;
- отправляет payload в query-параметр или POST form body;
- добавляет корреляционные заголовки:
  - `X-OAS-Test-Run`;
  - `X-OAS-Payload-Id`;
  - `X-OAS-Expected-Label`;
- пишет результат в JSONL и CSV;
- ограничивает скорость через `--rate`, чтобы не устроить DoS своему сервису;
- требует явный флаг `--i-am-authorized`, чтобы случайно не запустить трафик в чужую цель.

### Как сверять expected и actual

1. После запуска runner сохрани `run_id`, который он выводит в конце.
2. На сервере с NPM/open-appsec смотри события:

   ```bash
   docker logs appsec-agent --tail=1000 | jq -r 'select(tostring | contains("<RUN_ID>"))'
   tail -n 1000 ./appsec-logs/* 2>/dev/null | jq -r 'select(tostring | contains("<RUN_ID>"))'
   ```

3. В NPM UI открой **Security Log** и фильтруй по `X-OAS-Test-Run`/`X-OAS-Payload-Id`, если эти поля отображаются в конкретной версии UI.
4. Собери таблицу:

   | payload_id | expected_label | actual open-appsec event | HTTP status | вывод |
   |---|---|---|---:|---|
   | `oas-...-000001` | `true-positive` | detected/prevented | 200/403 | OK |
   | `oas-...-000002` | `true-positive` | no event | 200 | false negative |
   | `oas-...-000003` | `false-positive` | detected/prevented | 200/403 | false positive |

5. Для запуска в `Detect-Learn` нормальная ситуация, что HTTP status может быть `200`: важен не сам статус, а наличие security event в логах. В `Prevent-Learn` уже ожидай `403` для заблокированных атак.

### Безопасный порядок для production

1. Сначала `Detect-Learn` только на отдельном canary/staging host.
2. Первый прогон — маленький: `--limit 50 --rate 1`.
3. Проверить, что backend не меняет реальные данные.
4. Увеличивать до `--limit 200`, потом до полного набора.
5. Параллельно прогнать `false-positives.txt`/benign payloads с `--expected-label false-positive`.
6. Исправить false positives через policy/tuning/exclusions.
7. Повторить regression.
8. Только после стабильной картины включать `Prevent-Learn`, сначала на canary host, потом — на боевых hosts.

### Где тут NPM + open-appsec

Для production это всё еще нормальный вариант, если твой реальный ingress — NPM или ты готов завести canary через NPM. Он удобен тем, что:

- compose уже содержит отдельный `appsec-agent` и NPM attachment;
- Web UI позволяет включать WAF на конкретный Proxy Host;
- Security Log доступен прямо из NPM;
- persistent volumes можно бэкапить/переносить после обучения.

Если боевой ingress у тебя не NPM, а обычный NGINX/Kong/APISIX/Envoy, тогда NPM используй только для первого canary-прогона, а финальную проверку делай на том же ingress-классе, что и production.
