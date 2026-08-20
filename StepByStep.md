# SIEM Project: Complete Guide

This guide walks through building the project from an empty folder to a working dashboard. It matches the actual, currently-working configuration in this repo — every field name, script, and JSON block below is copied directly from the deployed files, not reconstructed from memory.

---

## 1. Prerequisites

- Docker Engine v20.10+ and Docker Compose v2.0+
- A terminal (PowerShell, Bash, etc.)
- Minimum 8 GB host RAM

## 2. Create the project folder and file tree

```bash
mkdir SIEM_Project && cd SIEM_Project
mkdir nginx docs docs/screenshots
```

Target structure:

```text
SIEM_Project/
├── docker-compose.yml
├── filebeat.yml
├── logstash.conf
├── siem-template.json
├── run_attacks.sh
├── additional_attacks.sh
├── nginx/
│   └── default.conf
├── .env.example
├── .gitignore
├── README.md
└── docs/
    └── screenshots/
```

## 3. Create each file

### 3.1 `docker-compose.yml`

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: elasticsearch
    mem_limit: 1g
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    cap_add:
      - IPC_LOCK
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:9200/_cluster/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 20
      start_period: 30s
    networks:
      - siem-network

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    container_name: logstash
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
      - ./siem-template.json:/usr/share/logstash/config/siem-template.json:ro
    environment:
      - LS_JAVA_OPTS=-Xms256m -Xmx256m
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'echo > /dev/tcp/127.0.0.1/9600' || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 20
      start_period: 60s
    networks:
      - siem-network
    depends_on:
      elasticsearch:
        condition: service_healthy

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: kibana
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY}
      - XPACK_SECURITY_ENCRYPTIONKEY=${XPACK_SECURITY_ENCRYPTIONKEY}
      - XPACK_REPORTING_ENCRYPTIONKEY=${XPACK_REPORTING_ENCRYPTIONKEY}
    networks:
      - siem-network
    depends_on:
      elasticsearch:
        condition: service_healthy
      logstash:
        condition: service_healthy

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.12.0
    container_name: filebeat
    user: root
    command: filebeat -e -strict.perms=false
    environment:
      - setup.template.settings.index.number_of_shards=1
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - nginx-logs:/var/log/nginx:ro
    networks:
      - siem-network
    depends_on:
      elasticsearch:
        condition: service_healthy
      logstash:
        condition: service_healthy

  web-server:
    image: nginx:latest
    container_name: web-server
    ports:
      - "8081:80"
    volumes:
      - nginx-logs:/var/log/nginx
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
    networks:
      - siem-network
    command: sh -c "rm -f /var/log/nginx/access.log /var/log/nginx/error.log && touch /var/log/nginx/access.log /var/log/nginx/error.log && nginx -g 'daemon off;'"

  attacker:
    image: kalilinux/kali-rolling
    container_name: attacker
    tty: true
    networks:
      - siem-network

networks:
  siem-network:
    driver: bridge

volumes:
  nginx-logs:
  esdata:
```

**Notes on choices made here:**
- `esdata` is a named volume so Elasticsearch survives `docker compose down` — without it, every restart wipes all indexed data *and* your saved Kibana Data View/dashboards/alert rules.
- The Logstash healthcheck uses a raw TCP check (`/dev/tcp`) instead of `curl`, because the official Logstash image (built on UBI9-minimal) doesn't ship `curl`. Using `curl` here silently deadlocks Kibana and Filebeat, since both `depends_on: condition: service_healthy` against Logstash.
- `web-server` mounts `./nginx/default.conf` explicitly — without this line, nginx silently falls back to its own factory-default config, and none of the customization in step 3.6 ever takes effect.

### 3.2 `filebeat.yml`

```yaml
filebeat.inputs:
- type: filestream
  id: nginx-logs
  enabled: true
  paths:
    - /var/log/nginx/access.log
    - /var/log/nginx/error.log
  fields:
    service: nginx
    type: nginx-access
  fields_under_root: true

output.logstash:
  hosts: ["logstash:5044"]
```

### 3.3 `logstash.conf`

```conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [log][file][path] =~ "/var/log/nginx" {
    if [log][file][path] =~ "access.log" {
      grok {
        match => { "message" => '%{IPORHOST:clientip} %{HTTPDUSER:ident} %{HTTPDUSER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-) %{QS:referrer} %{QS:http_user_agent} %{QS:xff}' }
        tag_on_failure => ["grok_failed"]
      }
    } else if [log][file][path] =~ "error.log" {
      grok {
        match => { "message" => '%{YEAR:year}/%{MONTHNUM:month}/%{MONTHDAY:day} %{TIME:time} \[%{LOGLEVEL:loglevel}\] %{NUMBER:pid}#%{NUMBER:tid}: (?:\*%{NUMBER:connection} )?(?:%{DATA:errormsg}, client: %{IP:clientip}, server: %{DATA:server}, request: \"%{WORD:method} %{DATA:request} HTTP/%{NUMBER:httpversion}\", host: \"%{DATA:http_host}\"|%{GREEDYDATA:errormsg})' }
        tag_on_failure => ["grok_failed"]
      }
    } else {
      grok {
        match => { "message" => '%{IPORHOST:clientip} %{HTTPDUSER:ident} %{HTTPDUSER:auth} \[%{HTTPDATE:timestamp}\] "(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})" %{NUMBER:response} (?:%{NUMBER:bytes}|-) %{QS:referrer} %{QS:http_user_agent} %{QS:xff}' }
        tag_on_failure => ["grok_failed"]
      }
    }

    # Strip the surrounding quotes %{QS} captures on agent/xff before they're used further.
    if [http_user_agent] {
      mutate { gsub => [ "http_user_agent", "^\"|\"$", "" ] }
    }
    if [xff] {
      mutate { gsub => [ "xff", "^\"|\"$", "" ] }
    }

    # Prefer X-Forwarded-For for GeoIP when present. In this lab, real traffic
    # comes from inside the Docker network (private IPs, which MaxMind can't
    # geolocate), so run_attacks.sh spoofs an X-Forwarded-For header with
    # real public DNS-resolver IPs to make the geographic map meaningful for
    # demonstration. This also mirrors a genuine production pattern: services
    # behind a reverse proxy/load balancer must GeoIP the forwarded client IP,
    # not the proxy's own address.
    if [xff] and [xff] != "-" and [xff] != "" {
      mutate { add_field => { "[network][geoip_source]" => "%{xff}" } }
    } else if [clientip] {
      mutate { add_field => { "[network][geoip_source]" => "%{clientip}" } }
    }

    if [network][geoip_source] {
      geoip {
        source => "[network][geoip_source]"
        target => "geoip"
        fields => ["country_name","city_name","location"]
        ecs_compatibility => "disabled"
      }
    }

    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z", "ISO8601", "yyyy/MM/dd HH:mm:ss" ]
      target => "@timestamp"
      remove_field => ["timestamp"]
    }

    mutate {
      rename => {
        "clientip" => "[source][address]"
        "verb" => "[http][request][method]"
        "request" => "[url][original]"
        "response" => "[http][response][status_code]"
        "http_user_agent" => "[user_agent][original]"
      }
      convert => { "[http][response][status_code]" => "integer" }
      convert => { "bytes" => "integer" }
    }

    # --- MITRE ATT&CK technique tagging ---
    # Event-level pattern matching for the dashboard's technique breakdown
    # panel. Mirrors the same conditions as the Kibana alert rules, but tags
    # every matching event individually rather than requiring a threshold
    # count over a 5-minute window. A single event can legitimately match
    # more than one technique, so these are independent `if` blocks, not
    # if/elsif — mutate's add_field appends rather than overwrites when a
    # field already has a value, so [mitre][technique_id] naturally becomes
    # an array when more than one condition matches.

    if [http][response][status_code] in [401, 403] {
      mutate {
        add_field => {
          "[mitre][technique_id]" => "T1110"
          "[mitre][technique_name]" => "Brute Force"
        }
      }
    }

    if [url][original] and [url][original] =~ /(?i)(drop|union|select|\bor\b)/ {
      mutate {
        add_field => {
          "[mitre][technique_id]" => "T1190"
          "[mitre][technique_name]" => "Exploit Public-Facing Application"
        }
      }
    }

    if [url][original] and [url][original] =~ /(\.\.\/|\.\.\\|%2e%2e)/ {
      mutate {
        add_field => {
          "[mitre][technique_id]" => "T1083"
          "[mitre][technique_name]" => "File and Directory Discovery"
        }
      }
    }

    if [user_agent][original] and [user_agent][original] =~ /(?i)(sqlmap|nikto|nmap|metasploit)/ {
      mutate {
        add_field => {
          "[mitre][technique_id]" => "T1595"
          "[mitre][technique_name]" => "Active Scanning"
        }
      }
    }

    if [http][response][status_code] and [http][response][status_code] >= 400 {
      mutate {
        add_field => {
          "[mitre][technique_id]" => "T1498"
          "[mitre][technique_name]" => "Network Denial of Service"
        }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    index => "siem-logs-%{+YYYY.MM.dd}"
    template => "/usr/share/logstash/config/siem-template.json"
    template_name => "siem-template"
    template_overwrite => true
  }

  stdout {
    codec => rubydebug
  }
}
```

**Why the grok pattern is written out manually instead of using `%{COMBINEDAPACHELOG}`:** Filebeat automatically adds its own `agent` metadata field to every event (`agent.type`, `agent.name`, `agent.id`, etc.). `%{COMBINEDAPACHELOG}`'s built-in field name for the HTTP User-Agent header is *also* `agent` — using it collides with Filebeat's field and corrupts the document, which Elasticsearch then rejects outright (this is what caused a full pipeline failure with `docs.count: 0` earlier in this project's history). The custom pattern above captures the same data into `http_user_agent` instead, avoiding the collision entirely.

### 3.4 `siem-template.json`

```json
{
  "index_patterns": ["siem-logs-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "geoip": {
          "properties": {
            "location": {
              "type": "geo_point"
            }
          }
        },
        "source": {
          "properties": {
            "address": {
              "type": "ip"
            }
          }
        },
        "http": {
          "properties": {
            "request": {
              "properties": {
                "method": {
                  "type": "keyword"
                }
              }
            },
            "response": {
              "properties": {
                "status_code": {
                  "type": "integer"
                }
              }
            }
          }
        },
        "url": {
          "properties": {
            "original": {
              "type": "keyword"
            }
          }
        },
        "user_agent": {
          "properties": {
            "original": {
              "type": "keyword"
            }
          }
        },
        "bytes": {
          "type": "integer"
        },
        "mitre": {
          "properties": {
            "technique_id": {
              "type": "keyword"
            },
            "technique_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}
```

Note `geoip.location` is flat, not nested under `geoip.geo.location`. Logstash 8.x's `geoip` filter defaults to ECS-compatible output (which nests under an extra `geo` level) — the `ecs_compatibility => "disabled"` line in `logstash.conf` above forces the flat shape this template expects.

### 3.5 `.env.example` and `.env`

```env
# Copy this file to .env and replace each value with your own generated key:
#   openssl rand -base64 32
#
# .env is gitignored — never commit real keys.

XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=replace_with_generated_key
XPACK_SECURITY_ENCRYPTIONKEY=replace_with_generated_key
XPACK_REPORTING_ENCRYPTIONKEY=replace_with_generated_key
```

```bash
cp .env.example .env
openssl rand -base64 32   # run 3 times, paste one result into each variable in .env
```

### 3.6 `nginx/default.conf`

```nginx
log_format siem_custom '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"';

server {
    listen 80;
    server_name localhost;

    access_log /var/log/nginx/access.log siem_custom;
    error_log /var/log/nginx/error.log warn;

    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}
```

### 3.7 `run_attacks.sh`

The full script is long (six attack categories, each looping tens to hundreds of requests). Rather than duplicate all ~110 lines here, copy it directly from the repo — the key structural points to understand:

- Every request runs via `docker exec -i attacker bash <<'ATTACKER_SCRIPT' ... ATTACKER_SCRIPT`, so traffic genuinely originates from the `attacker` container over the internal Docker network, not from your host.
- Every `curl` call sends `-H "X-Forwarded-For: $ip"`, cycling through a fixed list of real public DNS-resolver IPs (Google, Cloudflare, Quad9, Yandex, a Chinese/Korean/Brazilian/South African resolver) — this is what gives the GeoIP map something real to plot, since actual container-to-container traffic is private-IP-only and unmappable.
- One XSS payload is intentionally the *literal string* `$(whoami)` (escaped as `"\$(whoami)"`) — this demonstrates a command-injection-style payload without actually executing anything. If you ever see an **unescaped** `$(whoami)` in an attack script, that's a real bug: it executes for real wherever the script runs.

```bash
chmod +x run_attacks.sh
```

### 3.8 `additional_attacks.sh`

A second, complementary attack script covering categories `run_attacks.sh` doesn't: encoded path-traversal variants, command-injection query parameters, HTTP header injection probes, unusual HTTP methods (`TRACE`, `CONNECT`, etc.), common admin/config endpoint probing (`/wp-admin`, `/server-status`, `/.env`), and authentication anomalies with multiple credential pairs. Copy it from the repo as-is; it follows the same `docker exec -i attacker` pattern as `run_attacks.sh`.

```bash
chmod +x additional_attacks.sh
```

### 3.9 `.gitignore`

```gitignore
.env
__pycache__/
.DS_Store
```

---

## 4. Start the environment

```bash
docker compose up -d
sleep 60
docker compose ps
```

All six services should show `Up` (and `elasticsearch`/`logstash` should show `healthy` once the health checks pass). If any service is stuck in `Created` rather than `Up`, its `depends_on` condition never got satisfied — check that service's logs first.

```bash
curl http://localhost:9200          # Elasticsearch
curl http://localhost:5601          # Kibana
curl http://localhost:8081/         # web-server
```

## 5. Create the Kibana Data View

1. Open `http://localhost:5601`
2. **Stack Management → Data Views → Create data view**
3. Index pattern: `siem-logs-*`
4. Time field: `@timestamp`
5. Save

## 6. Generate traffic and confirm ingestion

```bash
bash run_attacks.sh
bash additional_attacks.sh
curl "http://localhost:9200/siem-logs-*/_count"
```

In Kibana **Discover**, select the `siem-logs-*` data view and confirm events appear with these fields populated:
- `source.address`, `http.request.method`, `http.response.status_code`, `url.original`, `user_agent.original`
- `geoip.location`, `geoip.country_name`, `geoip.city_name` (only present when `network.geoip_source` was set — check a few documents)
- `mitre.technique_id`, `mitre.technique_name` (only present on events matching a detection pattern)

Useful test filters:
```
http.response.status_code: (401 OR 403)
url.original: (*../* OR *..\\* OR *%2e%2e*)
user_agent.original: (*sqlmap* OR *nikto* OR *nmap* OR *metasploit*)
mitre.technique_id: *
```

## 7. Create the 5 detection rules

**Alerting → Create rule → Custom query rule (Query DSL)**, data view `siem-logs-*`, 5-minute time window on all five.

**Rule 1 — Brute Force (T1110):**
```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "query_string": { "query": "http.response.status_code:(401 OR 403)" } }
      ]
    }
  }
}
```
Threshold: count is above `5`.

**Rule 2 — SQL Injection (T1190):**
```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "query_string": { "query": "url.original:(*DROP* OR *UNION* OR *SELECT* OR *OR*)" } }
      ]
    }
  }
}
```
Threshold: count is above `5`.

**Rule 3 — Path Traversal (T1083):**
```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "query_string": { "query": "url.original:(*../* OR *..\\\\* OR *%2e%2e*)" } }
      ]
    }
  }
}
```
Threshold: count is above `5`.

**Rule 4 — Reconnaissance Tooling (T1595):**
```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "query_string": { "query": "user_agent.original:(*sqlmap* OR *nikto* OR *nmap* OR *metasploit*)" } }
      ]
    }
  }
}
```
Threshold: count is above `1`.

**Rule 5 — Volumetric Anomaly (T1498):**
```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "range": { "http.response.status_code": { "gte": 400 } } }
      ]
    }
  }
}
```
Threshold: count is above `10`.

If Kibana's URL-generation warning appears (`server.publicBaseUrl is not set`), set it under **Stack Management → Advanced Settings**, or ignore it — it doesn't affect rule evaluation, only shareable links.

## 8. Build the dashboard

Base panels (all `Terms`/`Date Histogram` bucket aggregations on `siem-logs-*`):

| Panel | Bucket | Field | Chart type |
|---|---|---|---|
| Attack Timeline | Date Histogram | `@timestamp` | Stacked bar (split by `http.response.status_code`) |
| Top Source IPs | Terms | `source.address` | Horizontal bar |
| Response Code Distribution | Terms | `http.response.status_code` | Donut |
| Suspicious URL Summary | Terms | `url.original` | Data table |
| Tool User-Agent Distribution | Terms | `user_agent.original` | Horizontal bar — add filter `NOT user_agent.original: curl*` to keep default curl noise from burying real scanner signatures |

Additional panels built on top of the base pipeline:

| Panel | Setup |
|---|---|
| Total Events (24h) | Metric, Count, no bucket |
| Unique Attacker IPs | Metric, Unique Count on `source.address` |
| High-Severity Hits | Metric, Count, filtered to `http.response.status_code >= 400` |
| MITRE ATT&CK Technique Breakdown | Terms on `mitre.technique_id`, horizontal bar |
| Geographic Attack Map | Kibana Maps → Documents layer → `geoip.location`, clustered |
| Raw Event Triage Table | Saved Discover search, filtered to `http.response.status_code >= 400`, columns: `@timestamp`, `source.address`, `http.response.status_code`, `url.original`, `user_agent.original` |

Save as **SIEM Attack Dashboard**.

## 9. Investigation and reporting

- **Discover:** sort by `@timestamp`, filter by `source.address` or `mitre.technique_id` to correlate activity.
- **Export evidence:** CSV export from Discover, plus dashboard screenshots.
- **Incident report:** summary, attack timeline, techniques observed (reference the MITRE table), source IPs, findings, recommended mitigations.

---

## Quick reference

```bash
docker compose up -d                                    # start
docker compose ps                                        # health check
curl "http://localhost:9200/siem-logs-*/_count"           # event count
bash run_attacks.sh && bash additional_attacks.sh          # generate traffic
docker logs logstash --tail 50                            # pipeline errors
```

## Troubleshooting

**No logs appearing:** `docker compose ps` — if `logstash` isn't `healthy`, Kibana/Filebeat never start (they depend on it). Check `docker logs logstash`.

**`geoip.location` has no data:** confirm `nginx/default.conf` is actually mounted (`docker exec web-server cat /etc/nginx/conf.d/default.conf | head -2` should show `siem_custom`, not the stock nginx format), and that `run_attacks.sh` ran after the container was up.

**Data disappeared after a restart:** confirm `esdata` is a named volume in `docker-compose.yml` and wasn't removed with `docker compose down -v`. Kibana Data Views/dashboards/rules live in Elasticsearch too, so wiping it wipes those as well.

**Alerts not firing:** confirm the rule's Query DSL field names match exactly (`http.response.status_code`, not `response`), and that the 5-minute window covers when `run_attacks.sh` actually ran.

## Screenshot reference

- `docs/screenshots/DockerContainers.png`
- `docs/screenshots/Discover_logs_details.png`
- `docs/screenshots/Bruteforce.png`
- `docs/screenshots/Bruteforce_details.png`
- `docs/screenshots/SQL_Injection_details.png`
- `docs/screenshots/PathTravesal.png`
- `docs/screenshots/Rules.png`
- `docs/screenshots/Dashboard_part1.png`
- `docs/screenshots/Dashboard_part2.png`
- `docs/screenshots/Dashboard_part3.png`