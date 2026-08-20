# Security Incident Report

## 1. Executive Summary

This report documents a controlled security incident simulation conducted in a containerized Security Information and Event Management (SIEM) laboratory environment.

The exercise was designed to demonstrate an end-to-end security monitoring workflow using Elasticsearch, Logstash, Kibana, Filebeat, and an NGINX web server. Attack traffic was generated from the isolated attacker container and monitored by the SIEM pipeline. The resulting events were indexed in Elasticsearch and investigated through Kibana Discover and detection rules.

The simulated activity included:

- HTTP brute-force authentication attempts
- Directory/path traversal attempts
- SQL injection payloads
- Cross-site scripting (XSS) payloads
- Suspicious security-scanner user agents
- Large HTTP POST requests intended to simulate volumetric anomalies

The activity was successfully ingested into the SIEM and made available for investigation using structured ECS-style fields such as `source.address`, `http.request.method`, `http.response.status_code`, `url.original`, and `user_agent.original`. Detection rules were configured around these fields using five-minute evaluation windows.

This was a **controlled laboratory simulation**. No evidence in the project documentation indicates that an external production system was compromised.

---

## 2. Incident Classification

| Category | Classification |
|---|---|
| Incident type | Controlled security simulation |
| Environment | Containerized SIEM laboratory |
| Primary target | NGINX web-server container |
| Monitoring platform | Elastic Stack |
| Log collection | Filebeat |
| Log processing | Logstash |
| Log storage | Elasticsearch |
| Investigation / visualization | Kibana |
| Attack source | Isolated attacker container |
| Severity | High for simulation purposes |
| Production compromise | Not identified |

---

## 3. Environment and Architecture

The laboratory uses the following monitoring architecture:

```text
NGINX Web Server
       |
       v
    Filebeat
       |
       v
    Logstash
       |
       v
 Elasticsearch
       |
       v
     Kibana
```

Attack traffic is generated from the attacker container and reaches the NGINX target through the Docker network. The project documentation describes this as an isolated laboratory workflow.

The primary investigation data is stored in the `siem-logs-*` index pattern.

---

## 4. Incident Description

The simulated incident consisted of multiple attack behaviors directed at the NGINX target.

The main attack script generates:

1. Repeated failed authentication attempts to simulate brute-force activity.
2. Path traversal requests targeting paths such as `../../../etc/passwd`.
3. SQL injection requests containing payloads such as `OR '1'='1'`, `UNION SELECT`, and `DROP TABLE`.
4. XSS payloads containing `<script>`, `<svg onload>`, and `<img onerror>`.
5. Requests using recognizable security-tool user agents including `sqlmap`, `nikto`, `nmap`, and `metasploit`.
6. Large POST bodies intended to produce anomalous HTTP traffic.

The project documentation identifies these behaviors as the intended threat simulation.

---

## 5. Attack Timeline

The simulated activity followed this general sequence:

### Phase 1 — Environment Preparation

The Docker environment was started and the Elasticsearch, Logstash, Kibana, Filebeat, NGINX, and attacker services were made available.

Baseline traffic was then generated to confirm that the logging pipeline was operating before malicious activity was introduced. The investigation workflow verifies that events are indexed in Elasticsearch and visible through the `siem-logs-*` data view.

### Phase 2 — Brute-Force Activity

Repeated authentication failures were generated against the NGINX target.

The detection logic searches for HTTP `401` and `403` responses:

```text
http.response.status_code:(401 OR 403)
```

The corresponding detection rule evaluates activity over a five-minute window.

### Phase 3 — Web Attack Activity

Path traversal and SQL injection payloads were sent against the target.

The SIEM uses `url.original` to investigate suspicious request content. SQL injection detection searches for patterns such as:

```text
*DROP*
*UNION*
*SELECT*
*OR*
```

Path traversal detection searches for patterns associated with `../`, encoded traversal, and related variants.

### Phase 4 — Reconnaissance and Malicious User Agents

Requests were generated using recognizable security-tool user agents, including:

- `sqlmap`
- `nikto`
- `nmap`
- `metasploit`

The corresponding detection rule examines `user_agent.original`.

### Phase 5 — HTTP Anomaly Activity

Large HTTP requests were generated to create a high-volume/anomalous traffic pattern.

The SIEM also includes an HTTP error-spike rule based on responses with status codes greater than or equal to 400.

---

## 6. Detection and Alerting

Five detection scenarios were configured:

| Detection | ECS Field | Detection Logic |
|---|---|---|
| Brute force | `http.response.status_code` | 401/403 responses |
| SQL injection | `url.original` | SQL-related payload patterns |
| Path traversal | `url.original` | Traversal patterns |
| Suspicious tooling | `user_agent.original` | Known scanner user agents |
| HTTP error anomaly | `http.response.status_code` | Status codes ≥ 400 |

The guide specifies Query DSL as the primary detection method and uses the actual parsed ECS-style fields produced by the pipeline.

The configured rules use five-minute windows, with thresholds selected to distinguish repeated attack activity from individual requests.

---

## 7. Investigation

The investigation was performed using Kibana Discover.

Investigators should sort events by `@timestamp` and examine:

- Repeated authentication failures
- Path traversal requests
- SQL injection payloads
- Suspicious security-tool user agents
- Large or malformed requests

The investigation can then be correlated by source IP using `source.address` and by time to identify periods of increased activity.

The principal ECS fields used during the investigation are:

```text
@timestamp
source.address
http.request.method
http.response.status_code
url.original
user_agent.original
```

These fields are also used for Kibana filtering, alerting, and dashboard visualization.

---

## 8. Evidence

The project contains visual evidence from the SIEM investigation, including:

- Docker container status
- Kibana Discover event details
- Brute-force alert
- Brute-force alert details
- SQL injection alert details

The README identifies the screenshot evidence under `docs/screenshots/`.

Additional evidence can be exported from Kibana as CSV files, including:

```text
attack_logs.csv
failed_logins.csv
traversal_requests.csv
sql_injection_requests.csv
suspicious_user_agents.csv
```

These correspond to the investigation evidence categories defined in the project workflow.

---

## 9. Impact Assessment

Because this was an isolated Docker-based simulation, the impact was limited to the laboratory environment.

The simulated attacks demonstrate potential impacts that would be relevant to a real web application:

- **Brute force:** potential unauthorized account access through credential guessing.
- **SQL injection:** potential unauthorized database access or manipulation.
- **Path traversal:** potential access to files outside an intended web directory.
- **XSS:** potential execution of attacker-controlled browser-side code.
- **Reconnaissance:** increased visibility into attacker tooling and scanning behavior.
- **Large HTTP requests:** potential resource exhaustion or denial-of-service conditions.

No claim is made that these attacks successfully compromised an actual production application. They were generated specifically to test the SIEM's detection and investigation capabilities.

---

## 10. Response and Containment

The simulated environment was already isolated within the Docker laboratory network.

The appropriate containment action for this exercise is therefore to terminate the generated attack traffic and preserve the resulting SIEM evidence for investigation.

Recommended laboratory response actions include:

1. Stop the attack simulation.
2. Preserve relevant Kibana screenshots and exported events.
3. Review triggered detection rules.
4. Correlate events by timestamp and source address.
5. Review the attack payloads and user-agent indicators.
6. Confirm that the target and monitoring containers remain operational.
7. Reset the laboratory environment if another clean test is required.

---

## 11. Recommendations

For a production environment, the following controls would be appropriate:

### Authentication

- Implement account lockout or progressive rate limiting.
- Enforce MFA for sensitive accounts.
- Monitor repeated authentication failures by source and account.

### Web Application Security

- Use parameterized SQL queries.
- Validate and sanitize user-controlled input.
- Apply output encoding to prevent XSS.
- Restrict file-system access to authorized directories.
- Deploy a Web Application Firewall where appropriate.

### Detection Engineering

- Continue using ECS-compatible field names consistently.
- Correlate multiple indicators instead of relying exclusively on individual signatures.
- Tune thresholds using normal traffic baselines.
- Add source-based rate detection.
- Add authentication/account correlation.
- Add detection for encoded and obfuscated attack payloads.

### Monitoring

- Retain sufficient logs for forensic investigation.
- Monitor anomalous request rates.
- Track suspicious user-agent activity.
- Monitor HTTP response-code spikes.
- Create dashboards showing attack trends over time.

---

## 12. MITRE ATT&CK Mapping

The simulated activity maps to several MITRE ATT&CK techniques:

| Activity | MITRE ATT&CK |
|---|---|
| Brute-force authentication | T1110 — Brute Force |
| SQL injection against web application | T1190 — Exploit Public-Facing Application |
| Path traversal / file discovery | T1083 — File and Directory Discovery |
| Scanner/reconnaissance tooling | T1595 — Active Scanning |
| Volumetric traffic anomaly | T1498 — Network Denial of Service |

These mappings are used by the project to connect individual detection scenarios with established adversary techniques.

---

## 13. Conclusion

The exercise successfully demonstrates a complete SIEM detection and investigation workflow.

Malicious traffic was generated in an isolated environment, collected by Filebeat, processed by Logstash, indexed in Elasticsearch, and investigated through Kibana. The detection rules use structured ECS-style fields to identify brute-force activity, SQL injection, path traversal, suspicious reconnaissance tooling, and HTTP anomalies.

The primary lesson from the exercise is that effective SIEM monitoring depends not only on generating security events but also on maintaining consistent field normalization, reliable log ingestion, meaningful detection logic, and a repeatable investigation process.

Because this was a controlled laboratory exercise, the final assessment is that the **simulated attack activity was detected and investigated successfully, with no evidence of compromise outside the intentionally targeted lab environment**.