"""Generate synthetic COMBINED/COMMON format logs for GoAccess testing."""
import random
from datetime import datetime, timedelta

# IPs from diverse geographic locations for geomap testing
IPS = [
    # North America
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222",
    "64.233.160.0", "72.14.192.0", "96.127.150.194",
    "104.16.132.229", "172.64.32.1", "198.41.0.4",
    # Europe
    "5.9.49.12", "5.9.49.13", "85.214.132.117",
    "185.199.108.153", "185.199.109.153", "91.189.89.49",
    "91.189.91.49", "194.154.205.26", "195.186.1.110",
    "88.198.0.1", "88.198.0.2",
    # Asia
    "168.63.129.16", "13.107.246.254", "20.53.203.50",
    "52.96.12.4", "52.96.16.100", "40.97.164.146",
    "103.152.220.6", "103.152.221.6",
    # South America
    "200.225.128.1", "200.225.129.1", "200.225.130.1",
    "177.71.128.1", "177.71.129.1",
    # Africa
    "41.76.108.46", "41.76.109.46", "41.76.110.46",
    "102.134.10.1", "102.134.11.1",
]

PATHS = [
    "/", "/index.html", "/about", "/contact", "/login",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png",
    "/admin/", "/admin/dashboard", "/admin/settings",
    "/blog", "/blog/post-1", "/blog/post-2", "/blog/post-3",
    "/docs", "/docs/api", "/docs/getting-started",
    "/health", "/metrics", "/robots.txt", "/sitemap.xml",
    "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
    "/.env", "/.git/config", "/etc/passwd",
    "/shell.php", "/cmd.php", "/eval-stdin.php",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
STATUSES = [200, 200, 200, 200, 200, 301, 304, 400, 401, 403, 404, 500]
SIZES = [0, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072]

REFERERS = [
    "-", "https://example.com/", "https://example.com/blog",
    "https://google.com/search?q=test", "https://bing.com/search?q=test",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "sqlmap/1.7.12", "nikto/2.5.0", "curl/8.4.0",
    "python-requests/2.31.0", "Go-http-client/2.0",
]

SECURITY_PATHS = [
    p for p in PATHS
    if any(x in p for x in [".env", ".git", "wp-", "shell", "cmd", "eval", "passwd"])
]


def _format_line(ip, timestamp, method, path, status, size, referer, ua):
    date_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{date_str}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def generate_log(lines=1000, log_format="COMBINED"):
    base_time = datetime.now() - timedelta(days=7)
    output = []

    for _ in range(lines):
        ts = base_time + timedelta(seconds=random.randint(0, 7 * 24 * 3600))
        ip = random.choice(IPS)
        referer = random.choice(REFERERS)
        ua = random.choice(USER_AGENTS)

        if random.random() < 0.05:
            method = random.choice(["GET", "POST"])
            path = random.choice(SECURITY_PATHS)
            status = random.choice([400, 401, 403, 404])
            size = random.choice([0, 128, 256])
        else:
            method = random.choice(METHODS)
            path = random.choice(PATHS)
            status = random.choice(STATUSES)
            size = random.choice(SIZES)

        line = _format_line(ip, ts, method, path, status, size, referer, ua)
        output.append((ts, line))

    output.sort(key=lambda x: x[0])
    return "\n".join(line for _, line in output)
