# SIEM Project: Complete Guide (All Phases 1–5)

This guide is written for someone starting from scratch with no project files provided. The user is expected to create the necessary project folder and configuration files manually before running the SIEM environment.

## 0. Fresh Start: Create the Project from Zero

If you are starting from a brand-new computer or a clean workspace, complete these steps first:

### Step 0.1: Install the required software
Install:
- Docker Desktop or Docker Engine
- Docker Compose
- A terminal such as PowerShell, Command Prompt, or Bash
- A text editor such as VS Code, Notepad++, or Nano

### Step 0.2: Create the project folder
Create a folder on your machine where the SIEM project will live. For example:

```bash
mkdir SIEM_Project
cd SIEM_Project
```

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Path .\SIEM_Project
Set-Location .\SIEM_Project
```

### Step 0.3: Use the project files provided in the repository

This guide describes the configuration that is actually present in the project. Do not recreate the Docker, Filebeat, Logstash, Elasticsearch template, NGINX, or attack-script files from configuration blocks copied out of this guide. Use the files in the repository so the documentation and the running environment stay synchronized.

The active project contains:

```text
SIEM_Project/
├── docker-compose.yml
├── filebeat.yml
├── logstash.conf
├── siem-template.json
├── run_attacks.sh
├── additional_attacks.sh
├── default.conf
├── nginx/
│   └── default.conf
├── .env
├── .gitignore
├── README.md
├── StepByStep_corrected.md
└── docs/
    └── screenshots/
```

The active Docker Compose file mounts `logstash.conf`, `siem-template.json`, `filebeat.yml`, and the shared NGINX log volume. It does **not** mount either `default.conf` file. NGINX therefore uses the configuration supplied by the `nginx:latest` image when the stack starts.

### Step 0.4: Confirm the repository files are present

From the project directory, verify the files before starting Docker:

```bash
ls
```

On Windows PowerShell:

```powershell
Get-ChildItem
```

Do not replace the repository configuration with copies embedded in this guide. The guide intentionally refers to the project files directly.

### Step 0.5: Configure the local environment

If the repository provides `.env.example`, copy it to `.env` and populate the three Kibana encryption-key variables. If `.env` is already provided for your local lab, use it as configured and do not commit real secrets.

```bash
cp .env.example .env
openssl rand -base64 64
```

Generate three unique values and place them in:

```env
XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=...
XPACK_SECURITY_ENCRYPTIONKEY=...
XPACK_REPORTING_ENCRYPTIONKEY=...
```

### Step 0.6: Final file creation checklist

Before starting Docker, make sure the repository contains the files used by the project:

- [ ] `docker-compose.yml`
- [ ] `filebeat.yml`
- [ ] `logstash.conf`
- [ ] `siem-template.json`
- [ ] `.env`
- [ ] `run_attacks.sh`
- [ ] `additional_attacks.sh`
- [ ] `README.md`
- [ ] `default.conf` / `nginx/default.conf` as repository files
- [ ] `docs/screenshots/`

### Step 0.6: Final file creation checklist
Before starting Docker, make sure the following files exist in the project folder:

- [ ] `docker-compose.yml`
- [ ] `filebeat.yml`
- [ ] `logstash.conf`
- [ ] `siem-template.json`
- [ ] `.env`
- [ ] `run_attacks.sh`
- [ ] `README.md`
- [ ] `.gitignore`

### Step 0.7: Configure Kibana in the GUI after startup
Once Docker is running, open Kibana in the browser:

```text
http://localhost:5601
```

Then complete the following GUI configuration steps.

#### A. Create the index pattern / data view
1. Open Kibana
2. Go to Stack Management
3. Select Data Views
4. Click Create data view
5. Enter `siem-logs-*` as the pattern
6. Set the time field to `@timestamp`
7. Save the data view

#### B. Validate the data in Discover
1. Open Discover
2. Choose the `siem-logs-*` data view
3. Confirm that events appear
4. Verify the following fields are present in the field list:
   - `@timestamp`
   - `source.address`
   - `http.request.method`
   - `http.response.status_code`
   - `url.original`
   - `user_agent.original`
5. Test a few filters:
   - `http.response.status_code: 200`
   - `http.response.status_code: (401 OR 403)`
   - `url.original: (*../* OR *..\\* OR *%2e%2e*)`
   - `user_agent.original: (*sqlmap* OR *nikto* OR *nmap* OR *metasploit*)`

#### C. Create the alert rules in the GUI
1. Open Alerting
2. Click Create rule
3. Select Custom query rule
4. Choose the `siem-logs-*` data view
5. Add the Query DSL rule using the syntax below
6. Set the threshold and time window
7. Save and enable the rule

Important: this lab uses Query DSL as the primary method. If Kibana shows the Log threshold rule by default, switch back to Custom query rule before entering the examples below.

Use the actual fields produced by the pipeline:
- `http.response.status_code`
- `url.original`
- `user_agent.original`
- `source.address`

Example Query DSL rules:

- Brute-force detection:
```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-5m" } } },

- SQL injection detection:
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

- Path traversal detection:
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

- Suspicious user-agent detection:
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

        { "range": { "@timestamp": { "gte": "now-5m" } } },
        { "range": { "http.response.status_code": { "gte": 400 } } }
      ]
    }
  }
}
```

Set the threshold to a value such as `is above 5` for repeated attack activity, and use a 5-minute time window for all examples.

#### D. Build a dashboard in the GUI
1. Open Dashboard
2. Click Create dashboard
3. Add the following visualizations using the actual parsed log fields:

   - Attack timeline
     - Metric: `Count`
     - Bucket: `Date Histogram`
     - Field: `@timestamp`

   - Top source IPs
     - Metric: `Count`
     - Bucket: `Terms`
     - Field: `source.address`

   - Response code distribution
     - Metric: `Count`
     - Bucket: `Terms`
     - Field: `http.response.status_code`

   - Suspicious URL summary
     - Metric: `Count`
     - Bucket: `Terms`
     - Field: `url.original`

   - Tool user-agent distribution
     - Metric: `Count`
     - Bucket: `Terms`
     - Field: `user_agent.original`

4. Set the user-agent panel to show the top 10 values so the tools stand out clearly.
5. Add optional filters for `curl`, `sqlmap`, `nikto`, and `nmap` when you want to isolate one tool at a time.

6. Save the dashboard as `SIEM Attack Dashboard`

### Dashboard validation checklist
- [ ] `curl`, `sqlmap`, `nikto`, and `nmap` appear in the user-agent chart

#### E. Final GUI check
Before continuing, confirm that:
- the data view exists
- Discover has logs
- alerts are active
- the dashboard loads with visualizations

This GUI setup is required for the phases that follow and is part of the lab workflow.

---

## Step-by-Step Order of Operations (A Version)

Use this exact order when starting from zero:

1. Install Docker Desktop / Docker Engine and Docker Compose
2. Create a project folder such as `SIEM_Project`
3. Create the following files:
   - `docker-compose.yml`
   - `filebeat.yml`
   - `logstash.conf`
   - `siem-template.json`
   - `.env`
   - `run_attacks.sh`
   - `README.md`
   - `.gitignore`
4. Save the correct content into each file
5. Rename `.env.example` to `.env` if using the example file
6. Make the attack script executable with `chmod +x run_attacks.sh`
7. Start the environment with `docker compose up -d`
8. Check container status with `docker ps`
9. Confirm Elasticsearch responds at `http://localhost:9200`
10. Confirm Kibana responds at `http://localhost:5601`
11. Open Kibana and create the `siem-logs-*` data view
12. Validate logs in Discover
13. Generate baseline traffic
14. Verify Elasticsearch document count is increasing
15. Run attack simulation with `bash run_attacks.sh`
16. Review malicious events in Discover
17. Create 5 Kibana alert rules
18. Test the rules and confirm alert activity
19. Build the dashboard with attack visualizations
20. Export CSV evidence and screenshots
21. Write the final incident report
22. Submit the final documentation package

---

## Phase 1: Setup and Environment Validation

### Objective
Set up the SIEM environment and confirm that all services are running correctly before generating suspicious traffic.

### 1. Start the environment from the project folder
Open a terminal and move into the project directory you created from scratch.

```bash
cd "C:/path/to/SIEM_Project"
docker compose up -d
```

If your machine uses Docker Compose v2, use:

```bash
docker compose up -d
```

If your folder is a different path, replace the path with your own created directory. The important point is that the user creates the folder and config files first, then starts the environment from there.

### 2. Check running containers

```bash
docker ps
```

You should see containers for Elasticsearch, Logstash, Kibana, Filebeat, the web target, and the attacker environment.

### 3. Validate the main services
Check Elasticsearch:

```bash
curl http://localhost:9200
```

Check Kibana:

```bash
curl http://localhost:5601
```

Check the web application:

```bash
curl http://localhost:8081/
```

### 4. Generate baseline traffic

```bash
for i in {1..50}; do
  curl http://localhost:8081/index.html -A "Mozilla/5.0" >/dev/null 2>&1
  sleep 0.3
done
```

### 5. Confirm log ingestion

```bash
curl -X GET "http://localhost:9200/siem-logs-*/_count"
```

### 6. Create the Kibana data view
In Kibana:
1. Open Stack Management
2. Select Data Views
3. Click Create data view
4. Use `siem-logs-*`
5. Set the time field to `@timestamp`
6. Save the view

### Phase 1 checklist
- [ ] Docker services are up
- [ ] Elasticsearch responds
- [ ] Kibana responds
- [ ] Web target responds
- [ ] Baseline traffic generated
- [ ] Logs are indexed
- [ ] Data view exists
- [ ] Logs appear in Discover

---

## Phase 2: Log Collection and Parsing Validation

### Objective
Make sure logs are being collected, parsed, and enriched properly before launching malicious traffic.

### 1. Review Logstash logs

```bash
docker logs -f logstash
```

### 2. Review Filebeat logs

```bash
docker logs -f filebeat
```

### 3. Inspect Elasticsearch records

```bash
curl -X GET "http://localhost:9200/siem-logs-*/_search?size=5"
```

### 4. Confirm expected fields
The pipeline should expose the following Logstash/Elasticsearch fields:
- `@timestamp`
- `source.address`
- `http.request.method`
- `http.response.status_code`
- `url.original`
- `user_agent.original`
- `bytes`

These are the actual ECS-style fields used by the working project and should be the ones referenced during investigation and rule creation.

### Phase 2 checklist
- [ ] Logstash container is running
- [ ] Filebeat is shipping events
- [ ] Elasticsearch contains documents
- [ ] Required fields are visible
- [ ] Discover is showing events

---

## Phase 3: Attack Simulation

The project has two attack scripts. `run_attacks.sh` is the primary simulation and sends spoofed `X-Forwarded-For` values so the GeoIP demonstration can use public IP addresses. `additional_attacks.sh` does **not** spoof `X-Forwarded-For`; its header-injection section sends a test `X-Forwarded-For` header as part of that probe.


### Objective
Generate realistic malicious traffic so the SIEM can detect suspicious patterns.

### 1. Brute-force login attempts

```bash
docker exec web-server bash -c "apt-get update && apt-get install -y apache2-utils && echo 'password123' | htpasswd -c -i /etc/nginx/.htpasswd admin"
```

```bash
for i in {1..100}; do
  curl -u admin:wrongpassword http://localhost:8081/ >/dev/null 2>&1
  sleep 0.1
done
```

### 2. Directory traversal attempts

```bash
for i in {1..50}; do
  curl "http://localhost:8081/../../../etc/passwd" >/dev/null 2>&1
  curl "http://localhost:8081/....//....//....//etc/passwd" >/dev/null 2>&1
done
```

### 3. SQL injection attempts

```bash
for i in {1..50}; do
  curl "http://localhost:8081/search?id=1' OR '1'='1" >/dev/null 2>&1
  curl "http://localhost:8081/search?id=DROP TABLE users--" >/dev/null 2>&1
done
```

### 4. XSS and command injection

```bash
for i in {1..30}; do
  curl "http://localhost:8081/search?q=<script>alert('xss')</script>" >/dev/null 2>&1
  curl "http://localhost:8081/cmd?param=$(whoami)" >/dev/null 2>&1
done
```

### 5. Suspicious scanning user-agent traffic

```bash
for i in {1..30}; do
  curl -A "curl/8.0" http://localhost:8081/ >/dev/null 2>&1
  curl -A "sqlmap/1.3" http://localhost:8081/ >/dev/null 2>&1
  curl -A "nikto/2.1" http://localhost:8081/ >/dev/null 2>&1
  curl -A "nmap/6.47" http://localhost:8081/ >/dev/null 2>&1
done
```

### 6. Large payloads

```bash
for i in {1..20}; do
  curl http://localhost:8081/ -d "$(python -c 'print("A" * 1000000)')" >/dev/null 2>&1
done
```

### 7. Optional full script

```bash
bash run_attacks.sh
```

### Important attacker-container note
If the attacker container does not already have `curl` installed, run:

```bash
docker exec -it attacker bash
apt-get update && apt-get install -y curl
```

This is required for generating the HTTP traffic that feeds the SIEM rules and dashboard.

### Phase 3 checklist
- [ ] failed login attempts created
- [ ] traversal attempts created
- [ ] SQL injection attempts created
- [ ] XSS or command injection attempts created
- [ ] suspicious scanning traffic created
- [ ] large payload traffic created
- [ ] suspicious events visible in Kibana

---

## Phase 4: Detection Rules and Alerting

### Objective
Create alerts that detect the malicious traffic generated in Phase 3 by using the actual fields produced by the pipeline.

### 1. Open Kibana Alerting
1. Go to Kibana
2. Open Alerting
3. Click Create rule
4. Choose Custom query rule
5. Select the `siem-logs-*` data view

### 2. Use Query DSL for all rules
This project uses Query DSL as the standard detection syntax. Do not switch to Log threshold for the examples below because the lab is designed around event-based matching against parsed HTTP fields.

### 3. Rule 1: Brute-force detection
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

Configure the rule as:
- Metric: `Count`
- Condition: `is above`
- Threshold: `5`
- Time window: `5m`

This rule identifies repeated login failures from one or more sources within a short interval.

### 4. Rule 2: SQL injection detection
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

This identifies requests containing SQL injection payloads in the URL.

### 5. Rule 3: Path traversal detection
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

This catches traversal attempts such as `../`, `%2e%2e`, and Windows-style encoded paths.

### 6. Rule 4: Suspicious user-agent detection
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

This catches traffic originating from known attacker toolsets.

### 7. Rule 5: HTTP error spike detection
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

Configure the rule to count events over a 5-minute window and trigger when the count exceeds a chosen threshold such as 5 or 10.

### Important: set the Kibana base URL
Before creating public alert links, set the Kibana base URL to:

```text
http://localhost:5601
```

This removes the warning:

> server.publicBaseUrl is not set. Generated URLs will either be relative or empty.

### Step-by-step Kibana verification before building rules
1. Open Kibana at `http://localhost:5601`
2. Go to Stack Management → Data Views
3. Create a data view named `siem-logs-*`
4. Set the time field to `@timestamp`
5. Open Discover and verify that events appear
6. Confirm the following fields exist:
   - `source.address`
   - `http.request.method`
   - `http.response.status_code`
   - `url.original`
   - `user_agent.original`
7. Test a few searches:
   - `source.address: *`
   - `http.response.status_code >= 400`
   - `url.original: *cmd*`
   - `user_agent.original: *sqlmap*`

### Phase 4 checklist
- [ ] Kibana public base URL is configured
- [ ] 5 rules created
- [ ] rule queries match the actual parsed log fields
- [ ] alerts fire with test traffic
- [ ] alert activity is visible in Kibana

---

## Phase 5: Investigation and Reporting

### Objective
Analyze the malicious events, correlate the patterns, and document the findings.

### 1. Use Kibana Discover
Sort by `@timestamp` and review the suspicious activity in order.
Look for:
- repeated failed logins
- traversal attacks
- SQL injection payloads
- suspicious user-agent tools
- large or malformed requests

### 2. Correlate by source IP
Filter by `source.address` and determine which source IP generated the most harmful activity.

### 3. Correlate by time window
Identify the time period when the attack activity surged.

### 4. Build a dashboard
Create visualizations for:
- attack timeline
- top source IPs
- response code distribution
- suspicious user-agent summary
- attack-type breakdown

### 5. Export evidence
Save CSV files or screenshots such as:
- `attack_logs.csv`
- `failed_logins.csv`
- `traversal_requests.csv`
- `sql_injection_requests.csv`
- `suspicious_user_agents.csv`

### 6. Write the incident report
The final write-up should include:
- summary of the incident
- attack timeline
- attack methods used
- source IPs involved
- findings from Kibana and alerting
- impact assessment
- recommended mitigation steps

### Phase 5 checklist
- [ ] timeline reviewed
- [ ] IP correlation complete
- [ ] time-based escalation identified
- [ ] dashboard created
- [ ] evidence exported
- [ ] final report written

---

## Quick reference commands

### Start environment from scratch
First create the project folder and all required files yourself. Then run:

```bash
cd "C:/path/to/SIEM_Project"
docker compose up -d
```

If Docker Compose v2 is installed, use:

```bash
docker compose up -d
```

### Check containers
```bash
docker ps
```

### Check Elasticsearch
```bash
curl http://localhost:9200
```

### Check Kibana
```bash
curl http://localhost:5601
```

### Review event count
```bash
curl -X GET "http://localhost:9200/siem-logs-*/_count"
```

### Run the full attack script
```bash
bash run_attacks.sh
```

---

## Troubleshooting

### No logs are appearing
Check the Docker state and service logs:

```bash
docker ps
docker logs logstash
docker logs filebeat
```

### Kibana shows no data
Make sure the data view exists and uses `siem-logs-*` with `@timestamp` as the time field.

### Web target is not responding

```bash
curl http://localhost:8081/
docker ps
```

### Alerts are not firing
Ensure the query matches the actual logged fields and that the time range includes the attack window.

---

## Final completion checklist

- [ ] environment started successfully
- [ ] logs are flowing into Elasticsearch
- [ ] Kibana data view created
- [ ] attack simulation performed
- [ ] malicious traffic visible in Discover
- [ ] 5 detection rules created
- [ ] alerts fired successfully
- [ ] dashboard created
- [ ] evidence exported
- [ ] final report completed

---

## Conclusion
This project models a complete end-to-end SIEM workflow. It demonstrates how to ingest logs, generate realistic malicious activity, create detection rules, and investigate the resulting attacks in a real security-monitoring environment.

## Screenshot References

The screenshots used as execution evidence are stored in the repository under `docs/screenshots/` and should be referenced with these exact relative paths:

- `docs/screenshots/DockerContainers.png`
- `docs/screenshots/Discover_logs_details.png`
- `docs/screenshots/Bruteforce.png`
- `docs/screenshots/Bruteforce_details.png`
- `docs/screenshots/SQL_Injection_details.png`