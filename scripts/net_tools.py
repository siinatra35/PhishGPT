"""
phishGPT Net Tools Worker
Polls the Flask queue for net_tools jobs and runs domain/IP reconnaissance:
  - Domain extraction
  - WHOIS lookup
  - DNS record enumeration
  - Geolocation (IP2Location)
  - ASN lookup
  - SSL certificate extraction

Results are written back to MongoDB.
"""

from datetime import datetime, timezone
from cymruwhois import Client as CymruClient
from dotenv import load_dotenv
import dns.resolver
import IP2Location
import tldextract
import pymongo
import logging
import socket
import json
import ssl
import os
import time
import requests

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("net_tools")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "gpt_app")
COLLECTION = os.getenv("DB_COLLECTION", "gpt_app")
BASE_APP = os.getenv("BASE_APP", "http://localhost:5000")
IP2LOC_DB_PATH = os.getenv("IP2LOC_DB_PATH", "/home/siinatra/code/phishGPT_2.0/IP2LOCATION-LITE-DB11.BIN")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "4"))

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "PTR", "NS", "MX", "TXT")

# ---------------------------------------------------------------------------
# Shared resources – initialised once
# ---------------------------------------------------------------------------
_mongo_client: pymongo.MongoClient | None = None
_ip2loc_db: IP2Location.IP2Location | None = None


def get_collection() -> pymongo.collection.Collection:
    global _mongo_client
    if _mongo_client is None:
        logger.info("Connecting to MongoDB at %s", DB_URL)
        _mongo_client = pymongo.MongoClient(DB_URL, serverSelectionTimeoutMS=5000)
    return _mongo_client[DB_NAME][COLLECTION]


def get_ip2loc() -> IP2Location.IP2Location:
    global _ip2loc_db
    if _ip2loc_db is None:
        logger.info("Loading IP2Location DB from %s", IP2LOC_DB_PATH)
        _ip2loc_db = IP2Location.IP2Location(IP2LOC_DB_PATH)
    return _ip2loc_db


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def set_job_status(job_id: str, status: str) -> None:
    """Set the net_tools_scan status field (In Progress / Complete)."""
    get_collection().update_one(
        {"_id": job_id},
        {"$set": {"net_tools_scan.status": status}},
    )


def save_results(job_id: str, results: dict) -> None:
    """Write all net_tools results and mark the job complete in one update."""
    get_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "net_tools_scan.status": "Complete",
                "net_tools_scan.result": results,
                "net_tools_scan.start_date": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    logger.info("job=%s results saved to DB", job_id)


# ---------------------------------------------------------------------------
# Recon functions
# ---------------------------------------------------------------------------
def extract_domain(url: str) -> str:
    """Pull the registrable domain (with subdomain if present) from a URL."""
    parts = tldextract.extract(url)
    if parts.subdomain:
        return f"{parts.subdomain}.{parts.domain}.{parts.suffix}"
    return f"{parts.domain}.{parts.suffix}"


def run_whois(domain: str) -> dict | str:
    """Run WHOIS on *domain*. Returns parsed dict or an error string."""
    try:
        import whois as python_whois
        data = python_whois.whois(domain)
        logger.info("WHOIS complete for %s", domain)
        return json.loads(str(data))
    except Exception:
        logger.warning("WHOIS lookup failed for %s", domain, exc_info=True)
        return f"Unable to perform WHOIS lookup for {domain}"


def enumerate_dns(domain: str) -> dict[str, list[str]]:
    """Resolve common DNS record types for *domain*."""
    results: dict[str, list[str]] = {rt: [] for rt in DNS_RECORD_TYPES}

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [rdata.to_text() for rdata in answers]
            logger.info("%s records found for %s: %d", record_type, domain, len(results[record_type]))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except Exception:
            logger.debug("DNS lookup %s/%s failed", domain, record_type, exc_info=True)
            continue

    return results


def get_geolocation(ip_address: str) -> dict | None:
    """Look up geolocation via IP2Location local DB."""
    try:
        rec = get_ip2loc().get_all(ip_address)
        if "INVALID IP ADDRESS" in str(rec):
            logger.warning("IP2Location reports invalid IP: %s", ip_address)
            return None
        geo = json.loads(str(rec).replace("'", '"'))
        logger.info("Geolocation resolved for %s", ip_address)
        return geo
    except Exception:
        logger.warning("Geolocation lookup failed for %s", ip_address, exc_info=True)
        return None


def get_asn(ip_address: str) -> str | None:
    """Query Team Cymru for ASN data."""
    try:
        result = CymruClient().lookup(ip_address)
        logger.info("ASN data found for %s: %s", ip_address, result)
        return str(result)
    except Exception:
        logger.warning("ASN lookup failed for %s", ip_address, exc_info=True)
        return None


def get_cert_data(domain: str, url: str) -> dict | str | None:
    """Extract the SSL/TLS certificate from *domain* if the URL is HTTPS."""
    if url.startswith("http://"):
        logger.info("Skipping cert extraction – HTTP-only URL for %s", domain)
        return "No certificate – site served over HTTP"

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we want the cert even if untrusted
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as conn:
            conn.settimeout(5.0)
            conn.connect((domain, 443))
            cert = conn.getpeercert(binary_form=False)
        logger.info("Certificate retrieved for %s", domain)
        return cert
    except Exception:
        logger.warning("Certificate extraction failed for %s", domain, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------
def run_safe(label: str, job_id: str, func, *args, **kwargs):
    """
    Run *func* and return its result.  If it raises, log the failure
    and return None so the rest of the pipeline keeps going.
    """
    try:
        return func(*args, **kwargs)
    except Exception:
        logger.exception("job=%s %s failed – storing null", job_id, label)
        return None


def _extract_url(data: dict) -> str:
    """
    Pull the final destination URL from redirect_data results.

    The redirect worker should store:
        data["redirect_data"]["result"]["final_url"]  (str in new format)
    or the legacy nested format:
        data["redirect_data"]["result"]["final_url"]["url"]

    If the result is missing, malformed, or still a placeholder string
    (e.g. "null"), fall back to the original URL on the job.
    """
    redirect = data.get("redirect_data", {})
    result = redirect.get("result") if isinstance(redirect, dict) else None

    if isinstance(result, dict):
        final = result.get("final_url")
        # new redirect_check stores final_url as a plain string
        if isinstance(final, str) and final:
            return final
        # legacy format nested one more level: {"url": "..."}
        if isinstance(final, dict):
            nested = final.get("url")
            if isinstance(nested, str) and nested:
                return nested

    # Fallback – use the original URL the job was created with
    fallback = data.get("url", "")
    if fallback:
        logger.warning(
            "job=%s redirect result missing or malformed – falling back to original URL: %s",
            data.get("_id", "unknown"), fallback,
        )
        return fallback

    raise ValueError(f"job={data.get('_id')} has no usable URL in redirect_data or top-level 'url' field")


def process_job(data: dict) -> None:
    """
    Run the full net_tools pipeline for a single queued job.

    Each enrichment step is independent — if one fails it is stored as
    None and the remaining steps still execute.
    """
    job_id: str = data["_id"]
    url: str = _extract_url(data)

    logger.info("job=%s starting net_tools scan on %s", job_id, url)
    set_job_status(job_id, "In Progress")

    # --- Domain extraction ---
    domain = run_safe("domain_extraction", job_id, extract_domain, url)
    logger.info("job=%s domain=%s", job_id, domain)

    # --- WHOIS ---
    whois_result = run_safe("whois", job_id, run_whois, domain) if domain else None

    # --- DNS ---
    dns_records = run_safe("dns_enum", job_id, enumerate_dns, domain) if domain else None

    # --- Geolocation & ASN (need an A record) ---
    a_records = (dns_records or {}).get("A", [])
    if a_records:
        primary_ip = a_records[0]
        geo = run_safe("geolocation", job_id, get_geolocation, primary_ip)
        asn = run_safe("asn", job_id, get_asn, primary_ip)
    else:
        if domain:
            logger.warning("job=%s no A records for %s – geo/ASN will be null", job_id, domain)
        geo = None
        asn = None

    # --- SSL certificate ---
    cert = run_safe("cert_data", job_id, get_cert_data, domain, url) if domain else None

    # --- Assemble and persist ---
    results = {
        "domain": domain,
        "dns_records": dns_records,
        "whois_scan": whois_result,
        "geolocation": geo,
        "ASN": asn,
        "cert_data": cert,
    }

    failed = [k for k, v in results.items() if v is None]
    if failed:
        logger.warning("job=%s completed with null fields: %s", job_id, ", ".join(failed))

    save_results(job_id, results)
    logger.info("job=%s net_tools scan complete", job_id)


def poll_queue() -> None:
    """Poll the Flask app for a net_tools job, process it if found."""
    try:
        resp = requests.get(f"{BASE_APP}/net_tools_queue", timeout=10)
    except requests.RequestException:
        logger.error("Failed to reach queue API at %s", BASE_APP, exc_info=True)
        return

    if resp.status_code != 200:
        logger.error("Queue API returned status %d", resp.status_code)
        return

    data = resp.json()
    if not data:
        logger.debug("No net_tools jobs in queue")
        return

    try:
        process_job(data)
    except Exception:
        # If process_job itself blows up (e.g. bad data shape, DB write
        # failure) we still log it but don't kill the worker loop.
        job_id = data.get("_id", "unknown")
        logger.exception("job=%s unhandled error in process_job", job_id)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Net tools worker starting – polling every %ds", POLL_INTERVAL)
    while True:
        poll_queue()
        time.sleep(POLL_INTERVAL)