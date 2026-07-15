import os


MIMIR_EXTERNAL_URL = os.environ.get(
    "MIMIR_EXTERNAL_URL", "https://arka.internal"
)
MIMIR_PROXY_HOST = os.environ.get(
    "MIMIR_PROXY_HOST", "proxy.arka.internal"
)
MIMIR_INPUT_DIR = os.environ.get(
    "MIMIR_INPUT_DIR", "/app/data/mimir/inputs"
)
MIMIR_REPORT_DIR = os.environ.get(
    "MIMIR_REPORT_DIR", "/app/data/mimir/reports"
)
MIMIR_TOKEN_TTL_MINUTES = int(
    os.environ.get("MIMIR_TOKEN_TTL_MINUTES", "15")
)
MIMIR_UPLOAD_MAX_SIZE = int(
    os.environ.get("MIMIR_UPLOAD_MAX_SIZE", str(500 * 1024 * 1024))
)
MIMIR_GEOIP_DB_PATH = os.environ.get(
    "MIMIR_GEOIP_DB_PATH", "/usr/share/GeoIP/dbip-city-lite.mmdb"
)
