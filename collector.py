import logging
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import psycopg2
import requests
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger("collector")

URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
SOURCE = "urlhaus"
IOC_TYPES = {"url", "ip", "domain", "md5", "sha1", "sha256"}
ALLOWED_SCHEMES = {"http", "https", "ftp"}
URLHAUS_DATE_FMT = "%Y-%m-%d %H:%M:%S UTC"


FAMILY_TAGS = {
    "rustystealer": "RustyStealer",
    "lummastealer": "LummaStealer",
    "mirai": "Mirai",
    "mozi": "Mozi",
    "vidar": "Vidar",
    "rhadamanthys": "Rhadamanthys",
    "santastealer": "SantaStealer",
    "agenttesla": "AgentTesla",
    "dropped-by-amadey": "Amadey",
}

UPSERT_SQL = """
INSERT INTO iocs (value, ioc_type, sources, family, status, tags, threat, first_seen)
VALUES (%(value)s, %(ioc_type)s, %(sources)s, %(family)s, %(status)s,
        %(tags)s, %(threat)s, %(first_seen)s)
ON CONFLICT (value, ioc_type) DO UPDATE SET
  first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
  last_seen  = now(),
  sources    = ARRAY(SELECT DISTINCT unnest(iocs.sources || EXCLUDED.sources)),
  tags       = ARRAY(SELECT DISTINCT unnest(
                 COALESCE(iocs.tags, '{}') || COALESCE(EXCLUDED.tags, '{}'))),
  family     = COALESCE(iocs.family, EXCLUDED.family),
  status     = COALESCE(EXCLUDED.status, iocs.status),
  threat     = COALESCE(EXCLUDED.threat, iocs.threat)
RETURNING (xmax = 0) AS inserted;
"""


# --------------------------------------------------------------------------
# 1. Fetch
# --------------------------------------------------------------------------
def fetch_recent(timeout: int = 30) -> list[dict]:
    key = os.getenv("ABUSECH_KEY")
    if not key:
        raise RuntimeError("ABUSECH_KEY is missing (check your .env file)")

    resp = requests.get(URLHAUS_RECENT, headers={"Auth-Key": key}, timeout=timeout)

    if resp.status_code == 401:
        raise RuntimeError("401 Unauthorized: Auth-Key is missing or invalid")
    if resp.status_code == 429:
        retry = resp.headers.get("Retry-After", "unknown")
        raise RuntimeError(f"429 Too Many Requests (Retry-After: {retry})")
    resp.raise_for_status()

    data = resp.json()
    if data.get("query_status") != "ok":
        raise RuntimeError(f"Unexpected query_status: {data.get('query_status')!r}")
    return data.get("urls") or []


# --------------------------------------------------------------------------
# 2. Normalize
# --------------------------------------------------------------------------
def refang(value: str) -> str:
    """Undo common defanging: hxxp:// -> http://, [.] -> ., [:] -> :"""
    v = value.strip()
    for old, new in (("hxxps://", "https://"), ("hxxp://", "http://"),
                     ("hXXp://", "http://"), ("[.]", "."), ("(.)", "."),
                     ("[:]", ":"), ("[://]", "://")):
        v = v.replace(old, new)
    return v


def parse_urlhaus_date(s) -> datetime:
    try:
        return datetime.strptime(s, URLHAUS_DATE_FMT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def normalize_url(raw_url: str) -> str | None:
    parts = urlsplit(refang(raw_url))
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return None
    try:
        host = parts.hostname      
        port = parts.port          
    except ValueError:
        return None
    if not host:
        return None
    if ":" in host:                
        host = f"[{host}]"
    userinfo = parts.netloc.rpartition("@")[0]   
    netloc = (f"{userinfo}@" if userinfo else "") + host + (f":{port}" if port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def pick_family(tags: list[str]) -> str | None:
    for t in tags:
        fam = FAMILY_TAGS.get(t.lower())
        if fam:
            return fam
    return None


def normalize(item: dict) -> dict | None:
    try:
        value = normalize_url(item.get("url") or "")
        if value is None:
            log.warning("Dropped invalid URL record id=%s url=%r", item.get("id"), item.get("url"))
            return None
        tags = [t.strip() for t in (item.get("tags") or []) if t and t.strip()]
        return {
            "value": value,
            "ioc_type": "url",
            "sources": [SOURCE],
            "family": pick_family(tags),
            "status": item.get("url_status"),
            "tags": tags,
            "threat": item.get("threat"),
            "first_seen": parse_urlhaus_date(item.get("date_added")),
        }
    except Exception:  
        log.exception("Failed to normalize record id=%s", item.get("id") if isinstance(item, dict) else "?")
        return None


def dedup_batch(iocs: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for ioc in iocs:
        key = (ioc["value"], ioc["ioc_type"])
        if key in seen:
            seen[key]["tags"] = sorted(set(seen[key]["tags"]) | set(ioc["tags"]))
        else:
            seen[key] = ioc
    return list(seen.values())


# --------------------------------------------------------------------------
# 3. Save
# --------------------------------------------------------------------------
def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "ioc"),
        password=os.getenv("DB_PASSWORD"),
        dbname=os.getenv("DB_NAME", "iocdb"),
    )


def save(conn, iocs: list[dict]) -> tuple[int, int]:
    inserted = updated = 0
    with conn.cursor() as cur:
        for ioc in iocs:
            assert ioc["ioc_type"] in IOC_TYPES, ioc["ioc_type"]
            cur.execute(UPSERT_SQL, ioc)
            if cur.fetchone()[0]:
                inserted += 1
            else:
                updated += 1
    conn.commit()
    return inserted, updated


# --------------------------------------------------------------------------
# 4. Main
# --------------------------------------------------------------------------
def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        items = fetch_recent()
    except Exception as e:
        log.error("Fetch failed: %s", e)
        return 1
    log.info("Fetched %d records", len(items))

    normalized = [n for n in (normalize(i) for i in items) if n]
    dropped = len(items) - len(normalized)
    unique = dedup_batch(normalized)
    dup_in_batch = len(normalized) - len(unique)

    conn = None
    try:
        conn = get_conn()
        inserted, updated = save(conn, unique)
    except Exception:
        if conn is not None:
            conn.rollback()
        log.exception("Database save failed")
        return 1
    finally:
        if conn is not None:
            conn.close()

    log.info("Done: new=%d already_existing=%d dropped_invalid=%d duplicates_in_batch=%d",
             inserted, updated, dropped, dup_in_batch)
    return 0


def run_loop() -> int:
    interval = int(os.getenv("COLLECT_INTERVAL", "0"))
    if interval <= 0:
        return main()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log.info("Loop mode: running every %d seconds", interval)
    while True:
        rc = main()
        if rc != 0:
            log.warning("Run failed (rc=%d), will retry in %d seconds", rc, interval)
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(run_loop())