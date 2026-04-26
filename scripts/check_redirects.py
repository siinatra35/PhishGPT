"""
phishGPT Redirect Checker Worker
Polls the Flask queue for redirect jobs, follows the URL to detect
redirects, captures response headers, and writes results back to MongoDB.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv
import pymongo
import logging
import json
import time
import os
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
logger = logging.getLogger("redirect")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_URL = os.getenv("DB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "gpt_app")
COLLECTION = os.getenv("DB_COLLECTION", "gpt_app")
BASE_APP = os.getenv("BASE_APP", "http://localhost:5000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "4"))
REQUEST_TIMEOUT = int(os.getenv("REDIRECT_TIMEOUT", "10"))

REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

# Extensions / domains to skip when the source is the phishgpt intake.
# Kept as a set of lowercased terms for O(1)-ish membership checks.
WHITELIST_TERMS = frozenset({
    ".png", ".jpg", ".jpeg", ".css", ".otf", ".gif",
    ".ttf", ".woff2",
    ".imgur.com", ".twitter.com", ".emltrk.com",
    ".thomsonreuters.com", ".exottogrow.info",
})

# ---------------------------------------------------------------------------
# MongoDB – single reusable client
# ---------------------------------------------------------------------------
_mongo_client: pymongo.MongoClient | None = None


def get_collection() -> pymongo.collection.Collection:
    global _mongo_client
    if _mongo_client is None:
        logger.info("Connecting to MongoDB at %s", DB_URL)
        _mongo_client = pymongo.MongoClient(DB_URL, serverSelectionTimeoutMS=5000)
    return _mongo_client[DB_NAME][COLLECTION]


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def set_job_status(job_id: str, status: str) -> None:
    get_collection().update_one(
        {"_id": job_id},
        {"$set": {"redirect_data.status": status}},
    )


def save_results(job_id: str, results: dict) -> None:
    """Persist redirect results in a single update."""
    get_collection().update_one(
        {"_id": job_id},
        {
            "$set": {
                "redirect_data.status": "Complete",
                "redirect_data.result": results,
                "redirect_data.start_date": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    logger.info("job=%s redirect results saved", job_id)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def normalise_url(url: str) -> str:
    """Ensure the URL has a scheme."""
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def is_whitelisted(url: str) -> bool:
    """Return True if the final URL matches any whitelist term."""
    lower = url.lower()
    return any(term in lower for term in WHITELIST_TERMS)


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------
def check_redirect(url: str) -> dict:
    """
    Follow *url* through any redirects and return structured results.

    Returns a dict with:
      - starting_url    : the original URL we were given
      - final_url       : where we ended up after redirects
      - is_redirect     : bool – did at least one redirect occur?
      - redirect_chain  : list of intermediate URLs (empty if no redirects)
      - domain_resolved : bool – did the request succeed at all?
      - response_headers: dict of final response headers (or None)
      - status_code     : final HTTP status code (or None)
    """
    url = normalise_url(url)

    result = {
        "starting_url": url,
        "final_url": url,
        "is_redirect": False,
        "redirect_chain": [],
        "domain_resolved": True,
        "response_headers": None,
        "status_code": None,
    }

    try:
        resp = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
        result["final_url"] = resp.url
        result["status_code"] = resp.status_code

        if resp.history:
            result["is_redirect"] = True
            result["redirect_chain"] = [
                {"url": r.url, "status_code": r.status_code}
                for r in resp.history
            ]

        # Capture response headers from the final hop
        try:
            result["response_headers"] = dict(resp.headers)
        except Exception:
            logger.warning("Could not serialise response headers for %s", url)

    except requests.exceptions.ConnectionError:
        logger.warning("Connection failed for %s – domain may not resolve", url)
        result["domain_resolved"] = False
    except requests.exceptions.Timeout:
        logger.warning("Request timed out for %s", url)
        result["domain_resolved"] = False
    except requests.exceptions.RequestException:
        logger.warning("Request error for %s", url, exc_info=True)
        result["domain_resolved"] = False

    return result


# ---------------------------------------------------------------------------
# Job processor
# ---------------------------------------------------------------------------
def process_job(data: dict) -> None:
    job_id: str = data["_id"]
    url: str = data["url"]
    source_tag: str = data.get("source_tag", "")

    logger.info("job=%s starting redirect check on %s", job_id, url)
    set_job_status(job_id, "In Progress")

    results = check_redirect(url)

    # If the source is the phishgpt intake, skip whitelisted URLs
    if source_tag == "phishgpt" and is_whitelisted(results["final_url"]):
        logger.info("job=%s final URL matched whitelist – skipping", job_id)
        results["whitelisted"] = True

    save_results(job_id, results)
    logger.info("job=%s redirect check complete – redirect=%s resolved=%s",
                job_id, results["is_redirect"], results["domain_resolved"])


# ---------------------------------------------------------------------------
# Queue poller
# ---------------------------------------------------------------------------
def poll_queue() -> None:
    try:
        resp = requests.get(f"{BASE_APP}/redirect_queue", timeout=10)
    except requests.RequestException:
        logger.error("Failed to reach queue API at %s", BASE_APP, exc_info=True)
        return

    if resp.status_code != 200:
        logger.error("Queue API returned status %d", resp.status_code)
        return

    data = resp.json()
    if not data:
        logger.debug("No redirect jobs in queue")
        return

    try:
        process_job(data)
    except Exception:
        job_id = data.get("_id", "unknown")
        logger.exception("job=%s unhandled error during redirect check", job_id)
        try:
            set_job_status(job_id, "Error")
        except Exception:
            logger.exception("job=%s failed to set Error status", job_id)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Redirect worker starting – polling every %ds", POLL_INTERVAL)
    while True:
        poll_queue()
        time.sleep(POLL_INTERVAL)