#!/bin/bash

set -e

echo "Starting attack simulations..."

docker exec web-server bash -c "
  apt-get update -qq && apt-get install -y -qq apache2-utils > /dev/null 2>&1 || true
  echo 'password123' | htpasswd -c -i /etc/nginx/.htpasswd admin 2>/dev/null || true
  cat > /etc/nginx/conf.d/auth.conf << 'CONF'
server {
    listen 80 default_server;

    location / {
        auth_basic \"Restricted Access\";
        auth_basic_user_file /etc/nginx/.htpasswd;
        root /usr/share/nginx/html;
        index index.html index.htm;
    }
}
CONF
  nginx -s reload 2>/dev/null || service nginx reload 2>/dev/null || true
" 2>/dev/null

docker exec -i attacker bash <<'ATTACKER_SCRIPT'
set -e

NGINX_URL="http://web-server"

command -v curl >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1)

# Real, well-known public DNS resolvers spanning several regions, used only
# as spoofed X-Forwarded-For values so the GeoIP map has something to plot.
# Traffic in this lab genuinely originates from the internal Docker network
# (private IPs), which MaxMind cannot geolocate — this header is what makes
# the "attack origin" map meaningful for demonstration purposes. It does not
# represent real attacker location.
GEO_IPS=(
  "8.8.8.8"          # Google DNS - US
  "1.1.1.1"          # Cloudflare - US
  "9.9.9.9"          # Quad9 - Switzerland
  "77.88.8.8"        # Yandex DNS - Russia
  "114.114.114.114"  # 114DNS - China
  "168.126.63.1"     # KT DNS - South Korea
  "200.221.11.100"   # Telefonica - Brazil
  "196.216.2.1"      # AFRINIC - South Africa
)

for i in {1..200}; do
  ip=${GEO_IPS[$((i % ${#GEO_IPS[@]}))]}
  curl -s -H "X-Forwarded-For: $ip" -u admin:wrongpassword "$NGINX_URL/index.html" > /dev/null 2>&1 &
done
wait

for i in {1..150}; do
  ip=${GEO_IPS[$((i % ${#GEO_IPS[@]}))]}
  curl -s -H "X-Forwarded-For: $ip" "$NGINX_URL/../../../etc/passwd" > /dev/null 2>&1 &
  curl -s -H "X-Forwarded-For: $ip" "$NGINX_URL/....//....//....//etc/passwd" > /dev/null 2>&1 &
done
wait

SQL_PAYLOADS=(
  "1' OR '1'='1"
  "1; DROP TABLE users--"
  "1' UNION SELECT * FROM users--"
  "1' AND 1=1--"
  "admin' --"
)

for i in {1..150}; do
  payload=${SQL_PAYLOADS[$((i % ${#SQL_PAYLOADS[@]}))]}
  ip=${GEO_IPS[$((i % ${#GEO_IPS[@]}))]}
  curl -s -H "X-Forwarded-For: $ip" "$NGINX_URL/search?id=$payload" > /dev/null 2>&1 &
done
wait

XSS_PAYLOADS=(
  "<script>alert('xss')</script>"
  "<img src=x onerror='alert(1)'>"
  "\$(whoami)"
  "<svg/onload=alert(1)>"
)

for i in {1..130}; do
  payload=${XSS_PAYLOADS[$((i % ${#XSS_PAYLOADS[@]}))]}
  ip=${GEO_IPS[$((i % ${#GEO_IPS[@]}))]}
  curl -s -H "X-Forwarded-For: $ip" "$NGINX_URL/search?q=$payload" > /dev/null 2>&1 &
done
wait

USER_AGENTS=(
  "sqlmap/1.3.8"
  "nikto/2.1.5"
  "nmap/7.80"
  "metasploit"
)

for i in {1..130}; do
  agent=${USER_AGENTS[$((i % ${#USER_AGENTS[@]}))]}
  ip=${GEO_IPS[$((i % ${#GEO_IPS[@]}))]}
  curl -s -H "X-Forwarded-For: $ip" -A "$agent" "$NGINX_URL/" > /dev/null 2>&1 &
done
wait

for i in {1..120}; do
  ip=${GEO_IPS[$((i % ${#GEO_IPS[@]}))]}
  LARGE_PAYLOAD=$(head -c 500000 </dev/zero | tr '\0' 'A')
  curl -s -H "X-Forwarded-For: $ip" -d "$LARGE_PAYLOAD" "$NGINX_URL/" > /dev/null 2>&1 &
done
wait

ATTACKER_SCRIPT

echo "Attack simulation complete."