# One-PC Docker guide: nginx + open-appsec v1beta2 + local Snort signatures

Этот гайд рассчитан на ситуацию: **на твоём ПК установлен только Docker**. Ниже есть copy-paste блок, который с нуля создаёт локальный стек:

```text
localhost:80
  -> appsec-nginx attachment
  -> appsec-agent
  -> juice-shop test backend

local policy: v1beta2
signatures: /etc/cp/conf/snort/custom-payloads.rules
режим сначала: detect-learn / snort detect
```

> Сначала подними это как локальный тест. После проверки меняй backend/host под свой сервис.

## 1. Copy-paste: создать и запустить весь локальный стек

Скопируй весь блок в терминал на своём ПК:

```bash
set -e

mkdir -p ~/oas-local-v1beta2
cd ~/oas-local-v1beta2

mkdir -p \
  appsec-config/snort \
  appsec-localconfig \
  appsec-data \
  appsec-logs \
  appsec-smartsync-storage \
  appsec-postgres-data \
  nginx-config \
  payloads-reviewed/sqli \
  runs

cat > docker-compose.yaml <<'YAML'
services:
  appsec-agent:
    image: ghcr.io/openappsec/agent:latest
    container_name: appsec-agent
    ipc: host
    restart: unless-stopped
    environment:
      - SHARED_STORAGE_HOST=appsec-shared-storage
      - LEARNING_HOST=appsec-smartsync
      - TUNING_HOST=appsec-tuning-svc
      - user_email=local@example.local
      - autoPolicyLoad=true
      - registered_server=NGINX
    volumes:
      - ./appsec-config:/etc/cp/conf
      - ./appsec-data:/etc/cp/data
      - ./appsec-logs:/var/log/nano_agent
      - ./appsec-localconfig:/ext/appsec
      - shm-volume:/dev/shm/check-point
    command: /cp-nano-agent

  appsec-nginx:
    image: ghcr.io/openappsec/nginx-attachment:latest
    container_name: appsec-nginx
    ipc: host
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-config:/etc/nginx/conf.d
      - shm-volume:/dev/shm/check-point
    depends_on:
      - appsec-agent
      - juiceshop-backend

  appsec-smartsync:
    image: ghcr.io/openappsec/smartsync:latest
    container_name: appsec-smartsync
    restart: unless-stopped
    environment:
      - SHARED_STORAGE_HOST=appsec-shared-storage
    depends_on:
      - appsec-shared-storage

  appsec-shared-storage:
    image: ghcr.io/openappsec/smartsync-shared-files:latest
    container_name: appsec-shared-storage
    ipc: host
    restart: unless-stopped
    user: root
    volumes:
      - ./appsec-smartsync-storage:/db:z

  appsec-tuning-svc:
    image: ghcr.io/openappsec/smartsync-tuning:latest
    container_name: appsec-tuning-svc
    restart: unless-stopped
    environment:
      - SHARED_STORAGE_HOST=appsec-shared-storage
      - QUERY_DB_PASSWORD=pass
      - QUERY_DB_HOST=appsec-db
      - QUERY_DB_USER=postgres
    volumes:
      - ./appsec-config:/etc/cp/conf
    depends_on:
      - appsec-shared-storage
      - appsec-db

  appsec-db:
    image: postgres:18
    container_name: appsec-db
    restart: unless-stopped
    environment:
      - POSTGRES_PASSWORD=pass
      - POSTGRES_USER=postgres
    volumes:
      - ./appsec-postgres-data:/var/lib/postgresql

  juiceshop-backend:
    image: bkimminich/juice-shop:latest
    container_name: juiceshop-backend
    restart: unless-stopped

volumes:
  shm-volume:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
YAML

cat > nginx-config/default.conf <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name _;

    location / {
        proxy_pass http://juiceshop-backend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

cat > appsec-config/local_policy.yaml <<'YAML'
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
YAML

# Дублируем policy в /ext/appsec на случай autoPolicyLoad-логики образа.
cp appsec-config/local_policy.yaml appsec-localconfig/local_policy.yaml

cat > appsec-config/snort/custom-payloads.rules <<'RULES'
# Local reviewed Snort signatures. Start in detect mode in local_policy.yaml.
alert http any any -> any any (msg:"local reviewed SQLi test 1"; flow:to_server; content:"1 OR 1=1"; http_uri; classtype:web-application-attack; sid:9100000; rev:1;)
alert http any any -> any any (msg:"local reviewed traversal test 1"; flow:to_server; content:"../etc/passwd"; http_uri; classtype:web-application-attack; sid:9100001; rev:1;)
RULES

cat > payloads-reviewed/sqli/true-positives.reviewed.txt <<'PAYLOADS'
1 OR 1=1
../etc/passwd
PAYLOADS

docker compose up -d

echo

echo '=== containers ==='
docker compose ps

echo

echo '=== wait 30s, then apply policy ==='
sleep 30
docker exec appsec-agent open-appsec-ctl --apply-policy || true

echo

echo '=== smoke requests ==='
curl -i 'http://127.0.0.1/' | head -20 || true
curl -i --get --data-urlencode 'q=1 OR 1=1' 'http://127.0.0.1/search' | head -30 || true

echo

echo '=== appsec logs tail ==='
docker logs appsec-agent --tail=120 || true
```

## 2. Что должно появиться

После запуска проверь:

```bash
cd ~/oas-local-v1beta2
docker compose ps
```

Ожидаемые контейнеры:

```text
appsec-agent
appsec-nginx
appsec-smartsync
appsec-shared-storage
appsec-tuning-svc
appsec-db
juiceshop-backend
```

Проверка HTTP:

```bash
curl -i http://127.0.0.1/
```

Проверка payload:

```bash
curl -i --get --data-urlencode 'q=1 OR 1=1' 'http://127.0.0.1/search'
```

В режиме `detect-learn` ответ может быть `200`. Смотри именно security event в логах:

```bash
docker logs appsec-agent --tail=300
```

## 3. Где лежат главные файлы

```text
~/oas-local-v1beta2/docker-compose.yaml
~/oas-local-v1beta2/nginx-config/default.conf
~/oas-local-v1beta2/appsec-config/local_policy.yaml
~/oas-local-v1beta2/appsec-localconfig/local_policy.yaml
~/oas-local-v1beta2/appsec-config/snort/custom-payloads.rules
~/oas-local-v1beta2/payloads-reviewed/sqli/true-positives.reviewed.txt
~/oas-local-v1beta2/runs/
```

Главный policy файл внутри agent:

```text
/etc/cp/conf/local_policy.yaml
```

Главный signatures файл внутри agent:

```text
/etc/cp/conf/snort/custom-payloads.rules
```

## 4. Как добавить свои payloads в signatures

Открой reviewed payload file:

```bash
cd ~/oas-local-v1beta2
nano payloads-reviewed/sqli/true-positives.reviewed.txt
```

Пример:

```text
1 OR 1=1
' OR '1'='1
../etc/passwd
```

Если у тебя есть этот репозиторий и Python, сгенерируй Snort rules helper-ом:

```bash
python3 scripts/payloads_to_snort.py \
  --input ~/oas-local-v1beta2/payloads-reviewed/sqli/true-positives.reviewed.txt \
  --output ~/oas-local-v1beta2/appsec-config/snort/custom-payloads.rules \
  --sid-start 9100000 \
  --http-buffer http_uri \
  --limit 100
```

Если Python/репозитория на этом ПК нет, добавляй rules руками в файл:

```bash
nano ~/oas-local-v1beta2/appsec-config/snort/custom-payloads.rules
```

Формат одной простой HTTP URI сигнатуры:

```text
alert http any any -> any any (msg:"local reviewed payload"; flow:to_server; content:"PAYLOAD_HERE"; http_uri; classtype:web-application-attack; sid:9100100; rev:1;)
```

После правки применить policy:

```bash
cd ~/oas-local-v1beta2
docker exec appsec-agent open-appsec-ctl --apply-policy
```

## 5. Как массово прогнать payloads без Python

Раз у тебя на ПК есть только Docker, можно прогонять через shell + curl:

```bash
cd ~/oas-local-v1beta2
RUN_ID="oas-$(date +%s)"
i=0
mkdir -p runs
: > "runs/${RUN_ID}.jsonl"

while IFS= read -r payload; do
  [ -z "$payload" ] && continue
  case "$payload" in \#*) continue ;; esac
  i=$((i+1))
  PID="${RUN_ID}-$(printf '%06d' "$i")"
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-OAS-Test-Run: ${RUN_ID}" \
    -H "X-OAS-Payload-Id: ${PID}" \
    -H "X-OAS-Expected-Label: true-positive" \
    --get --data-urlencode "q=${payload}" \
    'http://127.0.0.1/search' || true)
  printf '{"run_id":"%s","payload_id":"%s","expected_label":"true-positive","status":"%s"}\n' \
    "$RUN_ID" "$PID" "$code" | tee -a "runs/${RUN_ID}.jsonl"
  sleep 1
done < payloads-reviewed/sqli/true-positives.reviewed.txt

echo "RUN_ID=${RUN_ID}"
```

Ищи события:

```bash
docker logs appsec-agent --tail=1000 | grep "$RUN_ID" || true
```

## 6. Как массово прогнать payloads через payload_replay_runner.py

Если у тебя есть этот репозиторий и Python:

```bash
python3 scripts/payload_replay_runner.py \
  --base-url 'http://127.0.0.1/search' \
  --payload-file ~/oas-local-v1beta2/payloads-reviewed/sqli/true-positives.reviewed.txt \
  --param q \
  --method GET \
  --expected-label true-positive \
  --rate 1 \
  --limit 50 \
  --output ~/oas-local-v1beta2/runs/sqli-detect.jsonl \
  --i-am-authorized
```

## 7. Как локально выбирать true/false positive

### Вариант 1: expected labels в прогоне

Для malicious payloads:

```text
X-OAS-Expected-Label: true-positive
```

Для benign payloads:

```text
X-OAS-Expected-Label: false-positive
```

Таблица разбора:

| Expected | Есть open-appsec event | Вывод |
|---|---|---|
| true-positive | да | OK |
| true-positive | нет | false negative |
| false-positive | да | false positive |
| false-positive | нет | OK |

### Вариант 2: open-appsec-tuning-tool, если есть в контейнере

Найти tool:

```bash
docker exec -it appsec-agent sh -lc 'command -v open-appsec-tuning-tool || find / -name open-appsec-tuning-tool 2>/dev/null | head'
```

Запустить, если найден:

```bash
docker exec -it appsec-agent sh -lc 'open-appsec-tuning-tool || /open-appsec-tuning-tool'
```

Внутри tool логика такая:

```text
Manage tuning suggestions for learning
malicious = реальная атака / true positive
benign    = легитимно / false positive
```

Если tool отсутствует в конкретном образе, веди true/false positive через `runs/*.jsonl` и логи agent.

## 8. Перевести Snort signatures из detect в prevent

Открой policy:

```bash
nano ~/oas-local-v1beta2/appsec-config/local_policy.yaml
```

Замени:

```yaml
snortSignatures:
  overrideMode: detect
```

на:

```yaml
snortSignatures:
  overrideMode: prevent
```

Синхронизируй копию и примени:

```bash
cd ~/oas-local-v1beta2
cp appsec-config/local_policy.yaml appsec-localconfig/local_policy.yaml
docker exec appsec-agent open-appsec-ctl --apply-policy
```

Проверь payload ещё раз:

```bash
curl -i --get --data-urlencode 'q=1 OR 1=1' 'http://127.0.0.1/search'
docker logs appsec-agent --tail=300
```

## 9. Остановить / удалить стенд

Остановить:

```bash
cd ~/oas-local-v1beta2
docker compose down
```

Удалить данные полностью:

```bash
cd ~
rm -rf ~/oas-local-v1beta2
```

## 10. Когда переносить на свой сервис

После того как локально работает Juice Shop:

1. Замени `proxy_pass http://juiceshop-backend:3000;` в `nginx-config/default.conf` на свой upstream.
2. Перезапусти nginx:

```bash
cd ~/oas-local-v1beta2
docker compose restart appsec-nginx
```

3. Сначала оставь:

```yaml
policies:
  default:
    mode: detect-learn

snortSignatures:
  overrideMode: detect
```

4. Прогони benign и malicious payloads.
5. Только потом переводи signatures в `prevent`.
