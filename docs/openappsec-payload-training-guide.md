# Full-local nginx + open-appsec v1beta2: установка, Snort signatures из payloads и локальный true/false-positive workflow

Цель этого гайда: поднять **полностью локальный** стек `nginx + open-appsec`, сразу создать **Local Policy File v1beta2**, подключить свои payloads как **Snort signatures**, прогонять проверки и локально разбирать true/false positive без cloud.

> Важно: payloads не “скармливаются ML-модели” как обучение. Для детерминированного блокирования payloads их надо превращать в Snort/custom signatures и подключать через `snortSignatures.files` в v1beta2 policy.

## 0. Что получится в итоге

```text
[client / payload runner]
        -> [nginx attachment]
        -> [open-appsec agent]
        -> [your upstream app]

local files:
  ./openappsec/conf/local_policy.yaml
  ./openappsec/conf/snort/custom-payloads.rules
  ./openappsec/data/
  ./openappsec/logs/
```

Управление:

```bash
open-appsec-ctl --edit-policy
open-appsec-ctl --apply-policy
open-appsec-ctl --view-logs
./open-appsec-tuning-tool
```

## 1. Поставить nginx + open-appsec локально

### Вариант Linux installer

На сервере с nginx:

```bash
wget https://downloads.openappsec.io/open-appsec-install
chmod +x open-appsec-install
sudo ./open-appsec-install --auto
```

После установки проверь agent/CLI:

```bash
sudo open-appsec-ctl --status
sudo open-appsec-ctl --view-logs
```

### Вариант Docker

Для Docker используй официальный Docker deployment open-appsec, но сразу планируй persistent volumes:

```text
./openappsec/conf  -> /etc/cp/conf
./openappsec/data  -> /etc/cp/data
./openappsec/logs  -> /var/log/nano_agent
```

Файл `local_policy.yaml` сразу должен быть v1beta2 и лежать в mounted config directory, чтобы применять его через:

```bash
docker exec -it appsec-agent open-appsec-ctl --apply-policy
```

## 2. Сразу создать Local Policy File v1beta2

С нуля создай локальную конфигурацию сразу на v1beta2. Самый быстрый старт — скачать официальный пример v1beta2 policy:

```bash
mkdir -p ./openappsec/conf/snort ./openappsec/data ./openappsec/logs
wget https://raw.githubusercontent.com/openappsec/openappsec/main/config/linux/v1beta2/example/local_policy.yaml \
  -O ./openappsec/conf/local_policy.yaml
```

Для Linux deployment можно открыть policy через CLI:

```bash
sudo open-appsec-ctl --edit-policy
```

Для Docker deployment замени mounted файл:

```bash
cp ./openappsec/conf/local_policy.yaml /path/to/mounted/local_policy.yaml
```

После любой правки применяй policy:

```bash
sudo open-appsec-ctl --apply-policy
```

или для Docker:

```bash
docker exec -it appsec-agent open-appsec-ctl --apply-policy
```

## 3. Минимальный v1beta2 policy для Detect-Learn + Snort file

Ниже минимальный пример. Его можно использовать как стартовый шаблон и адаптировать hostname/upstream под свою схему.

```yaml
apiVersion: v1beta2

policies:
  default:
    mode: detect-learn
    threatPreventionPractices:
      - threat-prevention-practice
    accessControlPractices:
      - access-control-practice
    triggers:
      - log-trigger
    customResponse: web-user-response

threatPreventionPractices:
  - name: threat-prevention-practice
    practiceMode: inherited
    webAttacks:
      overrideMode: inherited
      minimumConfidence: high
    intrusionPrevention:
      overrideMode: inactive
      maxPerformanceImpact: medium
      minSeverityLevel: medium
      minCveYear: 2016
      highConfidenceEventAction: inherited
      mediumConfidenceEventAction: inherited
      lowConfidenceEventAction: detect
    fileSecurity:
      overrideMode: inactive
      minSeverityLevel: medium
      highConfidenceEventAction: inherited
      mediumConfidenceEventAction: inherited
      lowConfidenceEventAction: detect
    snortSignatures:
      overrideMode: detect
      configmap: []
      files:
        - /etc/cp/conf/snort/custom-payloads.rules
    schemaValidation:
      overrideMode: inactive
      configmap: []
      files: []
    antiBot:
      overrideMode: inactive
      injectedUris: []
      validatedUris: []

accessControlPractices:
  - name: access-control-practice
    practiceMode: inherited
    rateLimit:
      overrideMode: inactive
      rules: []

logTriggers:
  - name: log-trigger
    accessControlLogging:
      allowEvents: false
      dropEvents: true
    appsecLogging:
      detectEvents: true
      preventEvents: true
      allWebRequests: false
    extendedLogging:
      urlPath: true
      urlQuery: true
      httpHeaders: true
      requestBody: false
    additionalSuspiciousEventsLogging:
      enabled: true
      minSeverity: high
      responseBody: false
      responseCode: true
    logDestination:
      cloud: false
      logToAgent: true
      stdout:
        format: json

customResponses:
  - name: web-user-response
    mode: response-code-only
    httpResponseCode: 403
```

Проверка:

```bash
sudo open-appsec-ctl --apply-policy
sudo open-appsec-ctl --view-logs
```

Docker:

```bash
docker exec -it appsec-agent open-appsec-ctl --apply-policy
docker logs appsec-agent --tail=200
```

## 4. Подготовить payloads

Не подключай сырую папку `newpayloads-newpayloads` целиком. Сначала сделай reviewed набор.

Пример структуры:

```bash
mkdir -p ./payloads-reviewed/sqli ./payloads-reviewed/cmdexe ./payloads-reviewed/ssrf
```

Положи туда только payloads, которые ты реально хочешь превратить в signatures:

```text
./payloads-reviewed/sqli/true-positives.reviewed.txt
./payloads-reviewed/cmdexe/true-positives.reviewed.txt
./payloads-reviewed/ssrf/true-positives.reviewed.txt
```

Правило отбора:

```text
1 строка = 1 проверяемый payload/pattern
без мусора
без wordlists usernames/user-agents
без web-shell файлов целиком
без бинарей/архивов
без дублей
```

## 5. Сгенерировать Snort signatures из reviewed payloads

В репозитории есть helper:

```bash
python3 scripts/payloads_to_snort.py --help
```

Для URI/query payloads:

```bash
python3 scripts/payloads_to_snort.py \
  --input ./payloads-reviewed/sqli/true-positives.reviewed.txt \
  --output ./openappsec/conf/snort/custom-payloads.rules \
  --sid-start 9100000 \
  --http-buffer http_uri \
  --limit 100
```

Для POST body payloads:

```bash
python3 scripts/payloads_to_snort.py \
  --input ./payloads-reviewed/sqli/true-positives.reviewed.txt \
  --output ./openappsec/conf/snort/custom-payloads-body.rules \
  --sid-start 9110000 \
  --http-buffer http_client_body \
  --limit 100
```

Если v1beta2 поддерживает только `0 or 1 files` в `snortSignatures.files`, объедини rules в один файл:

```bash
cat ./openappsec/conf/snort/*.rules > ./openappsec/conf/snort/custom-payloads.rules
```

И в policy укажи один файл:

```yaml
snortSignatures:
  overrideMode: detect
  configmap: []
  files:
    - /etc/cp/conf/snort/custom-payloads.rules
```

## 6. Куда класть signatures

### Linux

```bash
sudo mkdir -p /etc/cp/conf/snort
sudo cp ./openappsec/conf/snort/custom-payloads.rules /etc/cp/conf/snort/custom-payloads.rules
sudo open-appsec-ctl --apply-policy
```

### Docker

Если volume смонтирован так:

```text
./openappsec/conf -> /etc/cp/conf
```

то файл на host:

```text
./openappsec/conf/snort/custom-payloads.rules
```

будет виден agent как:

```text
/etc/cp/conf/snort/custom-payloads.rules
```

Применить:

```bash
docker exec -it appsec-agent open-appsec-ctl --apply-policy
```

## 7. Проверить, что signatures применились

```bash
sudo open-appsec-ctl --view-logs
```

Docker:

```bash
docker logs appsec-agent --tail=300
```

Потом отправь тестовый payload:

```bash
curl -i 'https://your-host.example/search?q=1%20OR%201=1'
```

В `detect`/`detect-learn` HTTP-ответ может быть `200`; важен security event в логах. В `prevent`/`prevent-learn` ожидай блокировку, обычно `403`.

## 8. Запустить массовую проверку payloads

Runner нужен для воспроизводимого теста и корреляции с логами.

```bash
python3 scripts/payload_replay_runner.py \
  --base-url 'https://your-host.example/search' \
  --payload-file ./payloads-reviewed/sqli/true-positives.reviewed.txt \
  --param q \
  --method GET \
  --expected-label true-positive \
  --rate 1 \
  --limit 50 \
  --output ./runs/sqli-detect.jsonl \
  --i-am-authorized
```

Runner добавляет заголовки:

```text
X-OAS-Test-Run
X-OAS-Payload-Id
X-OAS-Expected-Label
```

По ним ищи события в логах:

```bash
docker logs appsec-agent --tail=1000 | grep 'X-OAS-Test-Run\|oas-'
```

## 9. Как локально работать с true/false positive

Есть два разных уровня.

### Уровень A: expected labels в runner

Для malicious payloads:

```bash
--expected-label true-positive
```

Для benign payloads, которые WAF не должен ловить:

```bash
--expected-label false-positive
```

Итоговая логика:

| Expected | Open-appsec event | Вывод |
|---|---|---|
| true-positive | есть detect/prevent event | OK |
| true-positive | нет event | false negative |
| false-positive | есть detect/prevent event | false positive |
| false-positive | нет event | OK |

### Уровень B: локальное tuning через CLI/tool

Если в твоей standalone/local установке есть `open-appsec-tuning-tool`, используй его для локальных tuning suggestions:

```bash
sudo ./open-appsec-tuning-tool
```

Или найди его:

```bash
which open-appsec-tuning-tool || sudo find / -name 'open-appsec-tuning-tool' 2>/dev/null
```

Дальше общий workflow:

```text
[2] Manage tuning suggestions for learning
выбрать suggestion
посмотреть связанные логи
решить: malicious или benign
```

Смысл:

```text
malicious = это реальная атака / true positive
benign    = это легитимно / false positive
```

Если `open-appsec-tuning-tool` в твоей версии отсутствует, остаётся внешний runner/report + правки policy/exceptions/signatures.

## 10. Перевести signatures из Detect в Prevent

Когда Snort signatures проверены:

```yaml
snortSignatures:
  overrideMode: prevent
  configmap: []
  files:
    - /etc/cp/conf/snort/custom-payloads.rules
```

Применить:

```bash
sudo open-appsec-ctl --apply-policy
```

Docker:

```bash
docker exec -it appsec-agent open-appsec-ctl --apply-policy
```

Снова прогнать runner и убедиться, что malicious payloads блокируются, а benign corpus не ловится.

## 11. Где здесь NPM

Если нужен именно NPM, используй его как отдельный следующий этап.

Сначала добейся, чтобы работал чистый full-local контур:

```text
nginx + open-appsec + v1beta2 + snortSignatures.files
```

Потом переносить в NPM.

Причина: текущий `open-appsec-npm-master` в этом репозитории использует v1beta1-style:

```yaml
snort-signatures:
  configmap: []
```

а тебе нужен v1beta2-style:

```yaml
snortSignatures:
  files:
    - /etc/cp/conf/snort/custom-payloads.rules
```

Поэтому для NPM есть 3 варианта:

1. найти свежий NPM/open-appsec image, который уже поддерживает v1beta2 local policy;
2. доработать NPM policy template/generator под v1beta2;
3. оставить NPM для обычного Detect-Learn/Web Attacks, а Snort files держать в отдельном local v1beta2 контуре.

## 12. Минимальная последовательность команд

```bash
# 1. поставить open-appsec
wget https://downloads.openappsec.io/open-appsec-install
chmod +x open-appsec-install
sudo ./open-appsec-install --auto

# 2. сразу создать v1beta2 policy
mkdir -p ./openappsec/conf/snort ./payloads-reviewed/sqli ./runs
wget https://raw.githubusercontent.com/openappsec/openappsec/main/config/linux/v1beta2/example/local_policy.yaml \
  -O ./openappsec/conf/local_policy.yaml

# 3. подготовить reviewed payloads
nano ./payloads-reviewed/sqli/true-positives.reviewed.txt

# 4. сгенерировать signatures
python3 scripts/payloads_to_snort.py \
  --input ./payloads-reviewed/sqli/true-positives.reviewed.txt \
  --output ./openappsec/conf/snort/custom-payloads.rules \
  --sid-start 9100000 \
  --http-buffer http_uri \
  --limit 100

# 5. скопировать signatures в agent config
sudo mkdir -p /etc/cp/conf/snort
sudo cp ./openappsec/conf/snort/custom-payloads.rules /etc/cp/conf/snort/custom-payloads.rules

# 6. отредактировать уже v1beta2 policy: snortSignatures.files
sudo open-appsec-ctl --edit-policy

# 7. применить
sudo open-appsec-ctl --apply-policy

# 8. проверить логи
sudo open-appsec-ctl --view-logs

# 9. прогнать payloads
python3 scripts/payload_replay_runner.py \
  --base-url 'https://your-host.example/search' \
  --payload-file ./payloads-reviewed/sqli/true-positives.reviewed.txt \
  --param q \
  --method GET \
  --expected-label true-positive \
  --rate 1 \
  --limit 50 \
  --output ./runs/sqli-detect.jsonl \
  --i-am-authorized

# 10. tuning если доступен
sudo ./open-appsec-tuning-tool
```
